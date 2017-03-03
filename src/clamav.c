/***

Copyright (C) 2015, 2016 Teclib'

This file is part of Armadito module clamav.

Armadito module clamav is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Armadito module clamav is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Armadito module clamav.  If not, see <http://www.gnu.org/licenses/>.

***/

#include <libarmadito/armadito.h>

#include "os/osdeps.h"

#include <assert.h>
#include <clamav.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define _XOPEN_SOURCE   /* FIXME: ...why? */
#include <time.h>

#include "os/osdeps.h"

struct clamav_data {
	struct cl_engine *clamav_engine;
	const char *db_dir;
	const char *tmp_dir;
	int late_days;
	int critical_days;
};

#define DEFAULT_LATE_DAYS (3)
#define DEFAULT_CRITICAL_DAYS (10)

static enum a6o_mod_status clamav_init(struct a6o_module *module)
{
	struct clamav_data *cl_data;
	int ret;
	const char *bases_location;
	size_t len;

	if ((ret = cl_init(CL_INIT_DEFAULT)) != CL_SUCCESS) {
		a6o_log(A6O_LOG_MODULE, A6O_LOG_LEVEL_ERROR, "ClamAV initialization failed: %s", cl_strerror(ret));
		return A6O_MOD_INIT_ERROR;
	}

	cl_data = malloc(sizeof(struct clamav_data));

	cl_data->clamav_engine = cl_engine_new();
	if(!cl_data->clamav_engine) {
		free(cl_data);
		a6o_log(A6O_LOG_MODULE, A6O_LOG_LEVEL_WARNING, "ClamAV: can't create new engine");
		return A6O_MOD_INIT_ERROR;
	}

	cl_data->db_dir = NULL;
	cl_data->tmp_dir = NULL;
	cl_data->late_days = DEFAULT_LATE_DAYS;
	cl_data->critical_days = DEFAULT_CRITICAL_DAYS;

	module->data = cl_data;

	return A6O_MOD_OK;
}

static enum a6o_mod_status clamav_conf_set_dbdir(struct a6o_module *module, const char *key, struct a6o_conf_value *value)
{
	struct clamav_data *cl_data = (struct clamav_data *)module->data;

	if (cl_data->db_dir != NULL)
		free((char *)cl_data->db_dir);

	cl_data->db_dir = os_strdup(a6o_conf_value_get_string(value));

	return A6O_MOD_OK;
}

static enum a6o_mod_status clamav_conf_set_tmpdir(struct a6o_module *module, const char *key, struct a6o_conf_value *value)
{
	struct clamav_data *cl_data = (struct clamav_data *)module->data;

	if (cl_data->tmp_dir != NULL)
		free((char *)cl_data->tmp_dir);

	cl_data->tmp_dir = os_strdup(a6o_conf_value_get_string(value));

	return A6O_MOD_OK;
}

static enum a6o_mod_status clamav_conf_set_late_days(struct a6o_module *module, const char *key, struct a6o_conf_value *value)
{
	struct clamav_data *cl_data = (struct clamav_data *)module->data;

	cl_data->late_days = a6o_conf_value_get_int(value);

	return A6O_MOD_OK;
}

static enum a6o_mod_status clamav_conf_set_critical_days(struct a6o_module *module, const char *key, struct a6o_conf_value *value)
{
	struct clamav_data *cl_data = (struct clamav_data *)module->data;

	cl_data->critical_days = a6o_conf_value_get_int(value);

	return A6O_MOD_OK;
}

static enum a6o_mod_status clamav_post_init(struct a6o_module *module)
{
	struct clamav_data *cl_data = (struct clamav_data *)module->data;
	int ret;
	unsigned int signature_count = 0;

	if (cl_data->tmp_dir != NULL) {
		if ((ret = cl_engine_set_str(cl_data->clamav_engine, CL_ENGINE_TMPDIR, cl_data->tmp_dir)) != CL_SUCCESS) {
			a6o_log(A6O_LOG_MODULE, A6O_LOG_LEVEL_WARNING, "ClamAV: error setting temporary directory: %s", cl_strerror(ret));
			cl_engine_free(cl_data->clamav_engine);
			cl_data->clamav_engine = NULL;
			return A6O_MOD_INIT_ERROR;
		}
	}

	if (cl_data->db_dir == NULL)
		cl_data->db_dir = os_strdup(cl_retdbdir());

	if ((ret = cl_load(cl_data->db_dir, cl_data->clamav_engine, &signature_count, CL_DB_STDOPT)) != CL_SUCCESS) {
		a6o_log(A6O_LOG_MODULE, A6O_LOG_LEVEL_WARNING, "ClamAV: error loading databases: %s", cl_strerror(ret));
		cl_engine_free(cl_data->clamav_engine);
		cl_data->clamav_engine = NULL;
		return A6O_MOD_INIT_ERROR;
	}

	a6o_log(A6O_LOG_MODULE, A6O_LOG_LEVEL_INFO, "ClamAV database loaded from %s, %d signatures", cl_data->db_dir, signature_count);

	if ((ret = cl_engine_compile(cl_data->clamav_engine)) != CL_SUCCESS) {
		a6o_log(A6O_LOG_MODULE, A6O_LOG_LEVEL_WARNING, "ClamAV: engine compilation error: %s", cl_strerror(ret));;
		cl_engine_free(cl_data->clamav_engine);
		cl_data->clamav_engine = NULL;
		return A6O_MOD_INIT_ERROR;
	}

	a6o_log(A6O_LOG_MODULE, A6O_LOG_LEVEL_INFO, "ClamAV is initialized");

	return A6O_MOD_OK;
}

static enum a6o_file_status clamav_scan(struct a6o_module *module, int fd, const char *path, const char *mime_type, char **pmod_report)
{
	struct clamav_data *cl_data = (struct clamav_data *)module->data;
	const char *virus_name = NULL;
	long unsigned int scanned = 0;
	int cl_scan_status;

	if (cl_data ->clamav_engine == NULL)
		return A6O_FILE_IERROR;

	cl_scan_status = cl_scandesc(fd, &virus_name, &scanned, cl_data->clamav_engine, CL_SCAN_STDOPT);

	if (cl_scan_status == CL_VIRUS) {
		*pmod_report = os_strdup(virus_name);

		return A6O_FILE_MALWARE;
	}

	return A6O_FILE_CLEAN;
}

static enum a6o_mod_status clamav_close(struct a6o_module *module)
{
	struct clamav_data *cl_data = (struct clamav_data *)module->data;
	int ret;

	if ((ret = cl_engine_free(cl_data->clamav_engine)) != CL_SUCCESS) {
		a6o_log(A6O_LOG_MODULE, A6O_LOG_LEVEL_WARNING, "ClamAV: can't free engine");
		return A6O_MOD_CLOSE_ERROR;
	}

	cl_data->clamav_engine = NULL;

	// Ulrich add
	cl_cleanup_crypto();

	return A6O_MOD_OK;
}

int get_late_days(time_t date)
{
	int late_days;
	time_t now = 0;
	double diffsec;

	time(&now);
	diffsec = difftime(now, date);
	late_days = (diffsec / (double)86400);

	return late_days;
}

static enum a6o_update_status clamav_update_status_eval(time_t timestamp, int late_days, int critical_days)
{
	int late;

	late = get_late_days(timestamp);

	if (late >= critical_days)
		return A6O_UPDATE_CRITICAL;
	else if (late >= late_days)
		return A6O_UPDATE_LATE;

	return A6O_UPDATE_OK;
}

static int get_month(const char *month){

	static const char *months = "JanFebMarAprMayJunJulAugSepOctNovDec";
	const char *ret;

	if ((ret = strstr(months, month)) == NULL)
	  return -1;

	return (ret - months) / 3;
}

// number of years after 1900 (/!\ should be >= 70 ).
static int get_year(int year){

	int ret = year - 1900;

	return (ret < 70 ? 70 : ret);
}


time_t get_timestamp(char * cvd_time)
{
	time_t cvd_timestamp = (time_t)-1;
	struct tm timeptr = {0};
	char s_month[4] = {0};
	char s_timezone[6] = {0};
	char tmpbuf[128] = {'\0'};
	char timebuf[26] = {0};
	int year = 0;

#ifdef _WIN32
	sscanf_s(cvd_time, "%d %3s %d %2d-%2d %5s",&timeptr.tm_mday, s_month,sizeof(s_month), &year, &timeptr.tm_hour, &timeptr.tm_min, s_timezone,sizeof(s_timezone));
#else
	sscanf(cvd_time, "%d %3s %d %2d-%2d %5s",&timeptr.tm_mday, s_month, &timeptr.tm_year, &timeptr.tm_hour, &timeptr.tm_min, s_timezone);
#endif

	timeptr.tm_isdst = 0;
	timeptr.tm_mon = get_month(s_month);
	timeptr.tm_sec = 0;
	timeptr.tm_year = get_year(year);

	cvd_timestamp = mktime(&timeptr);
	if (cvd_timestamp == (time_t)-1) {
		a6o_log(A6O_LOG_MODULE, A6O_LOG_LEVEL_ERROR, "get_timestamp :: mktime failed :: bad time format!");
		return cvd_timestamp;
	}

	return cvd_timestamp;
}

static enum a6o_update_status clamav_info(struct a6o_module *module, struct a6o_module_info *info)
{
	enum a6o_update_status status = A6O_UPDATE_NON_AVAILABLE;
	struct clamav_data *cl_data = (struct clamav_data *)module->data;
	char *dbnames[] = {"daily.cld", "daily.cvd", "main.cvd", "bytecode.cld", "bytecode.cvd"};
	int i, n, base_info_count;

	info->mod_update_ts = 0;

	n = sizeof(dbnames) / sizeof(const char *);

	info->base_infos = calloc(n + 1, sizeof(struct a6o_base_info*));

	base_info_count = 0;
	for (i = 0; i < n; i++) {
		char *full_path;
		char *version;
		struct a6o_base_info *base_info;
		struct cl_cvd *cvd;

		full_path = a6o_strcat(cl_data->db_dir, a6o_path_sep(), dbnames[i]);

		cvd = cl_cvdhead(full_path);
		if (cvd == NULL) {
			a6o_log(A6O_LOG_MODULE, A6O_LOG_LEVEL_WARNING, "clamav_info :: can't open cvd file! :: file = [%s]",full_path);
			free(full_path);
			continue;
		}

		base_info = malloc(sizeof(struct a6o_base_info));
		base_info->name = os_strdup(dbnames[i]);
		/* FD: note that in clamav.h stime field of cl_cvd is declared as "int", not as "time_t". So who's right? */
		base_info->base_update_ts = (time_t)cvd->stime;
		version = malloc(64);
		sprintf(version, "%d", cvd->version);
		base_info->version = version;
		base_info->signature_count = cvd->sigs;
		base_info->full_path = full_path;

		a6o_log(A6O_LOG_MODULE, A6O_LOG_LEVEL_DEBUG, "clamav_info :: name = %s", base_info->name);
		a6o_log(A6O_LOG_MODULE, A6O_LOG_LEVEL_DEBUG, "clamav_info :: fullpath = %s", base_info->full_path);
		a6o_log(A6O_LOG_MODULE, A6O_LOG_LEVEL_DEBUG, "clamav_info :: timestamp = %d", base_info->base_update_ts);
		a6o_log(A6O_LOG_MODULE, A6O_LOG_LEVEL_DEBUG, "clamav_info :: signatures = %d", base_info->signature_count);
		a6o_log(A6O_LOG_MODULE, A6O_LOG_LEVEL_DEBUG, "clamav_info :: version = %s", base_info->version);

		// module update date :: take the date of the most recent db file.
		if (base_info->base_update_ts > info->mod_update_ts)
			info->mod_update_ts = base_info->base_update_ts;

		info->base_infos[base_info_count++] = base_info;
	}

	// get module status according to db timestamp.
	status = clamav_update_status_eval(info->mod_update_ts, cl_data->late_days, cl_data->critical_days);

	return status;
}

static struct a6o_conf_entry clamav_conf_table[] = {
	{ "critical_days", CONF_TYPE_INT, clamav_conf_set_critical_days},
	{ "late_days", CONF_TYPE_INT, clamav_conf_set_late_days},
	{ "dbdir", CONF_TYPE_STRING, clamav_conf_set_dbdir},
	{ "tmpdir", CONF_TYPE_STRING, clamav_conf_set_tmpdir},
	{ NULL, CONF_TYPE_VOID, NULL},
};

static const char *clamav_mime_types[] = { "*", NULL, };

struct a6o_module module = {
	.init_fun = clamav_init,
	.conf_table = clamav_conf_table,
	.post_init_fun = clamav_post_init,
	.scan_fun = clamav_scan,
	.close_fun = clamav_close,
	.info_fun = clamav_info,
	.supported_mime_types = clamav_mime_types,
	.name = "clamav",
	.size = sizeof(struct clamav_data),
};
