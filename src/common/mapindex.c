/****************************************************************************!
*                _           _   _   _                                       *
*               | |__  _ __ / \ | |_| |__   ___ _ __   __ _                  *
*               | '_ \| '__/ _ \| __| '_ \ / _ \ '_ \ / _` |                 *
*               | |_) | | / ___ \ |_| | | |  __/ | | | (_| |                 *
*               |_.__/|_|/_/   \_\__|_| |_|\___|_| |_|\__,_|                 *
*                                                                            *
*                            www.brathena.org                                *
******************************************************************************
* src/common/mapindex.c                                                      *
******************************************************************************
* Copyright (c) brAthena Dev Team                                            *
* Copyright (c) Hercules Dev Team                                            *
* Copyright (c) Athena Dev Teams                                             *
*                                                                            *
* Licenciado sob a licen�a GNU GPL                                           *
* Para mais informa��es leia o arquivo LICENSE na ra�z do emulador           *
*****************************************************************************/

#define BRATHENA_CORE

#include "mapindex.h"

#include "common/cbasetypes.h"
#include "common/db.h"
#include "common/mmo.h"
#include "common/showmsg.h"
#include "common/strlib.h"

#include <stdio.h>
#include <stdlib.h>

/* mapindex.c interface source */
struct mapindex_interface mapindex_s;
struct mapindex_interface *mapindex;

// Lista de Mapas
const char *map_list[MAX_MAPINDEX] = {
	"alb_ship",
	"alb2trea",
	"alberta",
	"alberta_in",
	"alde_dun01",
	"alde_dun02",
	"alde_dun03",
	"alde_dun04",
	"aldeba_in",
	"aldebaran",
	"anthell01",
	"anthell02",
	"arena_room",
	"c_tower1",
	"c_tower2",
	"c_tower3",
	"c_tower4",
	"force_1-1",
	"force_1-2",
	"force_1-3",
	"force_2-1",
	"force_2-2",
	"force_2-3",
	"force_3-1",
	"force_3-2",
	"force_3-3",
	"gef_dun00",
	"gef_dun01",
	"gef_dun02",
	"gef_dun03",
	"gef_fild00",
	"gef_fild01",
	"gef_fild02",
	"gef_fild03",
	"gef_fild04",
	"gef_fild05",
	"gef_fild06",
	"gef_fild07",
	"gef_fild08",
	"gef_fild09",
	"gef_fild10",
	"gef_fild11",
	"gef_fild12",
	"gef_fild13",
	"gef_fild14",
	"gef_tower",
	"geffen",
	"geffen_in",
	"gl_cas01",
	"gl_cas02",
	"gl_church",
	"gl_chyard",
	"gl_dun01",
	"gl_dun02",
	"gl_in01",
	"gl_knt01",
	"gl_knt02",
	"gl_prison",
	"gl_prison1",
	"gl_sew01",
	"gl_sew02",
	"gl_sew03",
	"gl_sew04",
	"gl_step",
	"glast_01",
	"hunter_1-1",
	"hunter_2-1",
	"hunter_3-1",
	"in_hunter",
	"in_moc_16",
	"in_orcs01",
	"in_sphinx1",
	"in_sphinx2",
	"in_sphinx3",
	"in_sphinx4",
	"in_sphinx5",
	"iz_dun00",
	"iz_dun01",
	"iz_dun02",
	"iz_dun03",
	"iz_dun04",
	"job_sword1",
	"izlu2dun",
	"izlude",
	"izlude_in",
	"job_thief1",
	"knight_1-1",
	"knight_2-1",
	"knight_3-1",
	"mjo_dun01",
	"mjo_dun02",
	"mjo_dun03",
	"mjolnir_01",
	"mjolnir_02",
	"mjolnir_03",
	"mjolnir_04",
	"mjolnir_05",
	"mjolnir_06",
	"mjolnir_07",
	"mjolnir_08",
	"mjolnir_09",
	"mjolnir_10",
	"mjolnir_11",
	"mjolnir_12",
	"moc_castle",
	"moc_fild01",
	"moc_fild02",
	"moc_fild03",
	"moc_fild04",
	"moc_fild05",
	"moc_fild06",
	"moc_fild07",
	"moc_fild08",
	"moc_fild09",
	"moc_fild10",
	"moc_fild11",
	"moc_fild12",
	"moc_fild13",
	"moc_fild14",
	"moc_fild15",
	"moc_fild16",
	"moc_fild17",
	"moc_fild18",
	"moc_fild19",
	"moc_pryd01",
	"moc_pryd02",
	"moc_pryd03",
	"moc_pryd04",
	"moc_pryd05",
	"moc_pryd06",
	"moc_prydb1",
	"moc_ruins",
	"monk_in",
	"morocc",
	"morocc_in",
	"new_1-1",
	"new_1-2",
	"new_1-3",
	"new_1-4",
	"new_2-1",
	"new_2-2",
	"new_2-3",
	"new_2-4",
	"new_3-1",
	"new_3-2",
	"new_3-3",
	"new_3-4",
	"new_4-1",
	"new_4-2",
	"new_4-3",
	"new_4-4",
	"new_5-1",
	"new_5-2",
	"new_5-3",
	"new_5-4",
	"orcsdun01",
	"orcsdun02",
	"ordeal_1-1",
	"ordeal_1-2",
	//"ordeal_1-3",
	//"ordeal_1-4",
	"ordeal_2-1",
	"ordeal_2-2",
	//"ordeal_2-3",
	//"ordeal_2-4",
	"ordeal_3-1",
	"ordeal_3-2",
	//"ordeal_3-3",
	//"ordeal_3-4",
	"pay_arche",
	"pay_dun00",
	"pay_dun01",
	"pay_dun02",
	"pay_dun03",
	"pay_dun04",
	"pay_fild01",
	"pay_fild02",
	"pay_fild03",
	"pay_fild04",
	"pay_fild05",
	"pay_fild06",
	"pay_fild07",
	"pay_fild08",
	"pay_fild09",
	"pay_fild10",
	"pay_fild11",
	"payon",
	"payon_in01",
	"payon_in02",
	"priest_1-1",
	"priest_2-1",
	"priest_3-1",
	"prontera",
	"prt_are_in",
	"prt_are01",
	"pvp_room",
	"prt_castle",
	"prt_church",
	"prt_fild00",
	"prt_fild01",
	"prt_fild02",
	"prt_fild03",
	"prt_fild04",
	"prt_fild05",
	"prt_fild06",
	"prt_fild07",
	"prt_fild08",
	"prt_fild09",
	"prt_fild10",
	"prt_fild11",
	"prt_in",
	"prt_maze01",
	"prt_maze02",
	"prt_maze03",
	"prt_monk",
	"prt_sewb1",
	"prt_sewb2",
	"prt_sewb3",
	"prt_sewb4",
	"pvp_2vs2",
	"pvp_c_room",
	"pvp_n_1-1",
	"pvp_n_1-2",
	"pvp_n_1-3",
	"pvp_n_1-4",
	"pvp_n_1-5",
	"pvp_n_2-1",
	"pvp_n_2-2",
	"pvp_n_2-3",
	"pvp_n_2-4",
	"pvp_n_2-5",
	"pvp_n_3-1",
	"pvp_n_3-2",
	"pvp_n_3-3",
	"pvp_n_3-4",
	"pvp_n_3-5",
	"pvp_n_4-1",
	"pvp_n_4-2",
	"pvp_n_4-3",
	"pvp_n_4-4",
	"pvp_n_4-5",
	"pvp_n_5-1",
	"pvp_n_5-2",
	"pvp_n_5-3",
	"pvp_n_5-4",
	"pvp_n_5-5",
	"pvp_n_6-1",
	"pvp_n_6-2",
	"pvp_n_6-3",
	"pvp_n_6-4",
	"pvp_n_6-5",
	"pvp_n_7-1",
	"pvp_n_7-2",
	"pvp_n_7-3",
	"pvp_n_7-4",
	"pvp_n_7-5",
	"pvp_n_8-1",
	"pvp_n_8-2",
	"pvp_n_8-3",
	"pvp_n_8-4",
	"pvp_n_8-5",
	"pvp_n_room",
	"pvp_y_1-1",
	"pvp_y_1-2",
	"pvp_y_1-3",
	"pvp_y_1-4",
	"pvp_y_1-5",
	"pvp_y_2-1",
	"pvp_y_2-2",
	"pvp_y_2-3",
	"pvp_y_2-4",
	"pvp_y_2-5",
	"pvp_y_3-1",
	"pvp_y_3-2",
	"pvp_y_3-3",
	"pvp_y_3-4",
	"pvp_y_3-5",
	"pvp_y_4-1",
	"pvp_y_4-2",
	"pvp_y_4-3",
	"pvp_y_4-4",
	"pvp_y_4-5",
	"pvp_y_5-1",
	"pvp_y_5-2",
	"pvp_y_5-3",
	"pvp_y_5-4",
	"pvp_y_5-5",
	"pvp_y_6-1",
	"pvp_y_6-2",
	"pvp_y_6-3",
	"pvp_y_6-4",
	"pvp_y_6-5",
	"pvp_y_7-1",
	"pvp_y_7-2",
	"pvp_y_7-3",
	"pvp_y_7-4",
	"pvp_y_7-5",
	"pvp_y_8-1",
	"pvp_y_8-2",
	"pvp_y_8-3",
	"pvp_y_8-4",
	"pvp_y_8-5",
	"pvp_y_room",
	"sword_1-1",
	"sword_2-1",
	"sword_3-1",
	"treasure01",
	"treasure02",
	"wizard_1-1",
	"wizard_2-1",
	"wizard_3-1",
	"xmas",
	"xmas_dun01",
	"xmas_dun02",
	"xmas_fild01",
	"xmas_in",
	"beach_dun",
	"beach_dun2",
	"beach_dun3",
	"cmd_fild01",
	"cmd_fild02",
	"cmd_fild03",
	"cmd_fild04",
	"cmd_fild05",
	"cmd_fild06",
	"cmd_fild07",
	"cmd_fild08",
	"cmd_fild09",
	"cmd_in01",
	"cmd_in02",
	"comodo",
	"quiz_00",
	"quiz_01",
	"g_room1-1",
	"g_room1-2",
	"g_room1-3",
	"g_room2",
	"tur_dun01",
	"tur_dun02",
	"tur_dun03",
	"tur_dun04",
	"tur_dun05",
	"tur_dun06",
	"alde_gld",
	"aldeg_cas01",
	"aldeg_cas02",
	"aldeg_cas03",
	"aldeg_cas04",
	"aldeg_cas05",
	"gefg_cas01",
	"gefg_cas02",
	"gefg_cas03",
	"gefg_cas04",
	"gefg_cas05",
	"gld_dun01",
	"gld_dun02",
	"gld_dun03",
	"gld_dun04",
	"guild_room",
	"guild_vs1",
	"guild_vs2",
	"guild_vs3",
	"guild_vs4",
	"guild_vs5",
	"guild_vs1-1",
	"guild_vs1-2",
	"guild_vs1-3",
	"guild_vs1-4",
	"guild_vs2-1",
	"guild_vs2-2",
	"job_hunte",
	"job_knt",
	"job_prist",
	"job_wiz",
	"pay_gld",
	"payg_cas01",
	"payg_cas02",
	"payg_cas03",
	"payg_cas04",
	"payg_cas05",
	"prt_gld",
	"prtg_cas01",
	"prtg_cas02",
	"prtg_cas03",
	"prtg_cas04",
	"prtg_cas05",
	"alde_alche",
	"in_rogue",
	"job_cru",
	"job_duncer",
	"job_monk",
	"job_sage",
	"mag_dun01",
	"mag_dun02",
	"monk_test",
	"quiz_test",
	"yuno",
	"yuno_fild01",
	"yuno_fild02",
	"yuno_fild03",
	"yuno_fild04",
	"yuno_in01",
	"yuno_in02",
	"yuno_in03",
	"yuno_in04",
	"yuno_in05",
	"ama_dun01",
	"ama_dun02",
	"ama_dun03",
	"ama_fild01",
	"ama_in01",
	"ama_in02",
	"ama_test",
	"amatsu",
	"gon_dun01",
	"gon_dun02",
	"gon_dun03",
	"gon_fild01",
	"gon_in",
	"gon_test",
	"gonryun",
	"sec_in01",
	"sec_in02",
	"sec_pri",
	"umbala",
	"um_dun01",
	"um_dun02",
	"um_fild01",
	"um_fild02",
	"um_fild03",
	"um_fild04",
	"um_in",
	"niflheim",
	"nif_fild01",
	"nif_fild02",
	"nif_in",
	"yggdrasil01",
	"valkyrie",
	"himinn",
	"lou_in01",
	"lou_in02",
	"lou_dun03",
	"lou_dun02",
	"lou_dun01",
	"lou_fild01",
	"louyang",
	"siege_test",
	"n_castle",
	"nguild_gef",
	"nguild_prt",
	"nguild_pay",
	"nguild_alde",
	"jawaii",
	"jawaii_in",
	"gefenia01",
	"gefenia02",
	"gefenia03",
	"gefenia04",
	"new_zone01",
	"new_zone02",
	"new_zone03",
	"new_zone04",
	"payon_in03",
	"ayothaya",
	"ayo_in01",
	"ayo_in02",
	"ayo_fild01",
	"ayo_fild02",
	"ayo_dun01",
	"ayo_dun02",
	"que_god01",
	"que_god02",
	"yuno_fild05",
	"yuno_fild07",
	"yuno_fild08",
	"yuno_fild09",
	"yuno_fild11",
	"yuno_fild12",
	"alde_tt02",
	"turbo_n_1",
	"turbo_n_4",
	"turbo_n_8",
	"turbo_n_16",
	"turbo_e_4",
	"turbo_e_8",
	"turbo_e_16",
	"turbo_room",
	"airplane",
	"airport",
	"einbech",
	"einbroch",
	"ein_dun01",
	"ein_dun02",
	"ein_fild06",
	"ein_fild07",
	"ein_fild08",
	"ein_fild09",
	"ein_fild10",
	"ein_in01",
	"que_sign01",
	"que_sign02",
	"ein_fild03",
	"ein_fild04",
	"lhz_fild02",
	"lhz_fild03",
	"yuno_pre",
	"lhz_fild01",
	"lighthalzen",
	"lhz_in01",
	"lhz_in02",
	"lhz_in03",
	"lhz_que01",
	"lhz_dun01",
	"lhz_dun02",
	"lhz_dun03",
	"lhz_cube",
	"juperos_01",
	"juperos_02",
	"jupe_area1",
	"jupe_area2",
	"jupe_core",
	"jupe_ele",
	"jupe_ele_r",
	"jupe_gate",
	"y_airport",
	"lhz_airport",
	"airplane_01",
	"jupe_cave",
	"quiz_02",
	"hu_fild07",
	"hu_fild05",
	"hu_fild04",
	"hu_fild01",
	"yuno_fild06",
	"job_soul",
	"job_star",
	"que_job01",
	"que_job02",
	"que_job03",
	"abyss_01",
	"abyss_02",
	"abyss_03",
	"thana_step",
	"thana_boss",
	"tha_scene01",
	"tha_t01",
	"tha_t02",
	"tha_t03",
	"tha_t04",
	"tha_t07",
	"tha_t05",
	"tha_t06",
	"tha_t08",
	"tha_t09",
	"tha_t10",
	"tha_t11",
	"tha_t12",
	"auction_01",
	"auction_02",
	"hugel",
	"hu_in01",
	"que_bingo",
	"que_hugel",
	"p_track01",
	"p_track02",
	"odin_tem01",
	"odin_tem02",
	"odin_tem03",
	"hu_fild02",
	"hu_fild03",
	"hu_fild06",
	"ein_fild01",
	"ein_fild02",
	"ein_fild05",
	"yuno_fild10",
	"kh_kiehl02",
	"kh_kiehl01",
	"kh_dun02",
	"kh_dun01",
	"kh_mansion",
	"kh_rossi",
	"kh_school",
	"kh_vila",
	"force_map1",
	"force_map2",
	"force_map3",
	"job_hunter",
	"job_knight",
	"job_priest",
	"job_wizard",
	"ve_in02",
	"rachel",
	"ra_in01",
	"ra_fild01",
	"ra_fild02",
	"ra_fild03",
	"ra_fild04",
	"ra_fild05",
	"ra_fild06",
	"ra_fild07",
	"ra_fild08",
	"ra_fild09",
	"ra_fild10",
	"ra_fild11",
	"ra_fild12",
	"ra_fild13",
	"ra_san01",
	"ra_san02",
	"ra_san03",
	"ra_san04",
	"ra_san05",
	"ra_temin",
	"ra_temple",
	"ra_temsky",
	"que_rachel",
	"ice_dun01",
	"ice_dun02",
	"ice_dun03",
	"ice_dun04",
	"que_thor",
	"thor_camp",
	"thor_v01",
	"thor_v02",
	"thor_v03",
	"veins",
	"ve_in",
	"ve_fild01",
	"ve_fild02",
	"ve_fild03",
	"ve_fild04",
	"ve_fild05",
	"ve_fild06",
	"ve_fild07",
	"poring_c01",
	"poring_c02",
	"que_ng",
	"nameless_i",
	"nameless_n",
	"nameless_in",
	"abbey01",
	"abbey02",
	"abbey03",
	"poring_w01",
	"poring_w02",
	"que_san04",
	"moscovia",
	"mosk_in",
	"mosk_ship",
	"mosk_fild01",
	"mosk_fild02",
	"mosk_dun01",
	"mosk_dun02",
	"mosk_dun03",
	"mosk_que",
	"force_4-1",
	"force_5-1",
	"06guild_r",
	"06guild_01",
	"06guild_02",
	"06guild_03",
	"06guild_04",
	"06guild_05",
	"06guild_06",
	"06guild_07",
	"06guild_08",
	"z_agit",
	"que_temsky",
	"itemmall",
	"bossnia_01",
	"bossnia_02",
	"bossnia_03",
	"bossnia_04",
	"schg_cas01",
	"schg_cas02",
	"schg_cas03",
	"schg_cas04",
	"schg_cas05",
	"sch_gld",
	"cave",
	"moc_fild20",
	"moc_fild21",
	"moc_fild22",
	"que_ba",
	"que_moc_16",
	"que_moon",
	"arug_cas01",
	"arug_cas02",
	"arug_cas03",
	"arug_cas04",
	"arug_cas05",
	"aru_gld",
	"bat_room",
	"bat_a01",
	"bat_a02",
	"bat_b01",
	"bat_b02",
	"que_qsch01",
	"que_qsch02",
	"que_qsch03",
	"que_qsch04",
	"que_qsch05",
	"que_qaru01",
	"que_qaru02",
	"que_qaru03",
	"que_qaru04",
	"que_qaru05",
	"1@cata",
	"2@cata",
	"e_tower",
	"1@tower",
	"2@tower",
	"3@tower",
	"4@tower",
	"5@tower",
	"6@tower",
	"mid_camp",
	"mid_campin",
	"man_fild01",
	"man_fild03",
	"spl_fild02",
	"spl_fild03",
	"moc_fild22b",
	"que_dan01",
	"que_dan02",
	"schg_que01",
	"schg_dun01",
	"arug_que01",
	"arug_dun01",
	"1@orcs",
	"2@orcs",
	"1@nyd",
	"2@nyd",
	"nyd_dun01",
	"nyd_dun02",
	"manuk",
	"man_fild02",
	"man_in01",
	"splendide",
	"spl_fild01",
	"spl_in01",
	"spl_in02",
	"bat_c01",
	"bat_c02",
	"bat_c03",
	"moc_para01",
	"job3_arch01",
	"job3_arch02",
	"job3_arch03",
	"job3_guil01",
	"job3_guil02",
	"job3_guil03",
	"job3_rang01",
	"job3_rang02",
	"job3_rune01",
	"job3_rune02",
	"job3_rune03",
	"job3_war01",
	"job3_war02",
	"jupe_core2",
	"brasilis",
	"bra_in01",
	"bra_fild01",
	"bra_dun01",
	"bra_dun02",
	"dicastes01",
	"dicastes02",
	"dic_in01",
	"dic_fild01",
	"dic_fild02",
	"dic_dun01",
	"dic_dun02",
	"job3_gen01",
	"s_atelier",
	"job3_sha01",
	//"evt_zombie",
	//"evt_coke",
	//"ac_sl_area",
	//"ac_cl_hall",
	//"ac_cl_room",
	//"jp_s_dun11",
	"mora",
	"bif_fild01",
	"bif_fild02",
	"1@mist",
	"dewata",
	"dew_in01",
	"dew_fild01",
	"dew_dun01",
	"dew_dun02",
	"que_house_s",
	"malangdo",
	"mal_in01",
	"mal_in02",
	"mal_dun01",
	"1@pump",
	"2@pump",
	"1@cash",
	"iz_dun05",
	"evt_mobroom",
	"alde_tt03",
	"dic_dun03",
	//"mjolnir_04_1",
	//"evt_swar_b",
	//"evt_swar_r",
	//"evt_swar_s",
	//"evt_swar_t",
	"1@lhz",
	"lhz_dun04",
	"que_lhz",
	"gld_dun01_2",
	"gld_dun02_2",
	"gld_dun03_2",
	"gld_dun04_2",
	"gld2_ald",
	"gld2_gef",
	"gld2_pay",
	"gld2_prt",
	"malaya",
	"ma_fild01",
	"ma_fild02",
	"ma_scene01",
	"ma_in01",
	"ma_dun01",
	"1@ma_h",
	"1@ma_c",
	"1@ma_b",
	"ma_zif01",
	"ma_zif02",
	"ma_zif03",
	"ma_zif04",
	"ma_zif05",
	"ma_zif06",
	"ma_zif07",
	"ma_zif08",
	"ma_zif09",
	"job_ko",
	"eclage",
	"ecl_fild01",
	"ecl_in01",
	"ecl_in02",
	"ecl_in03",
	"ecl_in04",
	"1@ecl",
	"ecl_tdun01",
	"ecl_tdun02",
	"ecl_tdun03",
	"ecl_tdun04",
	"ecl_hub01",
	"que_avan01",
	"moc_prydn1",
	"moc_prydn2",
	"iz_int",
	"iz_int01",
	"iz_int02",
	"iz_int03",
	"iz_int04",
	"iz_ac01",
	"iz_ac02",
	"iz_ng01",
	"treasure_n1",
	"treasure_n2",
	"iz_ac01_d",
	"iz_ac02_d",
	"iz_ac01_c",
	"iz_ac02_c",
	"iz_ac01_b",
	"iz_ac02_b",
	"iz_ac01_a",
	"iz_ac02_a",
	"izlude_d",
	"izlude_c",
	"izlude_b",
	"izlude_a",
	"prt_fild08d",
	"prt_fild08c",
	"prt_fild08b",
	"prt_fild08a",
	"te_prt_gld",
	"te_prtcas01",
	"te_prtcas02",
	"te_prtcas03",
	"te_prtcas04",
	"te_prtcas05",
	"teg_dun01",
	"teg_dun02",
	"te_alde_gld",
	"te_aldecas1",
	"te_aldecas2",
	"te_aldecas3",
	"te_aldecas4",
	"te_aldecas5",
	"1@gl_k",
	"2@gl_k",
	"gl_cas02_",
	"gl_chyard_",
	"silk_lair",
	"evt_bomb",
	"1@def01",
	"1@def02",
	"1@def03",
	"1@face",
	"1@sara",
	"dali",
	"dali02",
	"1@tnm1",
	"1@tnm2",
	"1@tnm3",
	"1@ge_st",
	"1@gef",
	"1@gef_in",
	"1@spa",
	"moro_vol",
	"moro_cav",
	"1@dth1",
	"1@dth2",
	"1@dth3",
	"1@rev",
	"1@xm_d",
	"1@eom",
	"1@jtb",
	"c_tower2_",
	"c_tower3_",
	"1@gl_kh",
	"2@gl_kh",
	"e_hugel",
	"ver_eju",
	"ver_tunn",
	"verus03",
	"verus04",
	"1@mcd",
	"job_gun",
	"1@glast",
	"1@air1",
	"1@air2",
	"lhz_dun_n",
	"verus01",
	"verus02",
	"un_bk_q",
	"un_bunker",
	"un_myst",
	"1@uns",
	"1@lab",
	"paramk",
	"1@infi",
	"1@ffp",
	//"pud_land",
	//"1@pda",
	//"1@pdb",
	"1@mir",
	"2@mir",
	"1@sthb",
	"1@sthc",
	"1@sthd",
	"prt_cas",
	"prt_cas_q",
	"prt_prison",
	"prt_lib",
	"prt_lib_q",
	"prt_q",
	"prt_pri00",
	"int_land",
	"int_land01",
	"int_land02",
	"int_land03",
	"int_land04",
	"lasagna",
	"lasa_fild01",
	"lasa_fild02",
	"lasa_dun01",
	"lasa_dun02",
	"lasa_dun03",
	"conch_in",
	"lasa_in01",
	"lasa_dun_q",
	"1@pop1",
	"1@pop2",
	"1@pop3",
	//"payon_p",
	"1@slw",
	"1@swat",
	"que_swat",
	"slabw01",
	"rebel_in",
	//"rwc01",
	//"rwc02",
	//"rwc03",
	//"2009rwc_f01",
	//"2009rwc_01",
	//"2009rwc_02",
	//"2009rwc_03",
	//"2009rwc_04",
	//"2008rwc_04",
	//"prontera_x",
	//"alberta_x",
	//"aldebaran_x",
	//"geffen_x",
	//"izlude_x",
	//"prt_church_x",
	//"prontera_s",
	//"pay_arche_s",
	//"xmas_old",
	//"ordeal_a00",
	//"ordeal_a02",
	//"fay_vilg00",
	//"fay_vilg01",
	//"gef_vilg00",
	//"gef_vilg01",
	//"moc_dugn01",
	//"moc_dugn02",
	//"moc_fild01",
	//"moc_fild02",
	//"moc_fild03",
	//"moc_fild04",
	//"moc_intr00",
	//"moc_intr01",
	//"moc_intr02",
	//"moc_intr04",
	//"moc_vilg00",
	//"moc_vilg01",
	//"moc_vilg02",
	//"probemap",
	//"probemap02",
	//"prt_cstl01",
	//"prt_dugn00",
	//"prt_dugn01",
	//"prt_fild00",
	//"prt_fild01",
	//"prt_fild03",
	//"prt_fild04",
	//"prt_fild05",
	//"prt_intr01",
	//"prt_intr01_a",
	//"prt_intr02",
	//"prt_vilg00",
	//"prt_vilg01",
	//"prt_vilg02",
	//"tank_test",
	//"tank_test2",
	//"test",

	/** Mapas Personalizados **/
	"custom_map"
};

/// Retrieves the map name from 'string' (removing .gat extension if present).
/// Result gets placed either into 'buf' or in a static local buffer.
const char* mapindex_getmapname(const char* string, char* output) {
	static char buf[MAP_NAME_LENGTH];
	char* dest = (output != NULL) ? output : buf;

	size_t len = strnlen(string, MAP_NAME_LENGTH_EXT);
	if (len == MAP_NAME_LENGTH_EXT) {
		ShowWarning("(mapindex_normalize_name) Nome do mapa '%*s' muito extenso!\n", 2*MAP_NAME_LENGTH_EXT, string);
		len--;
	}
	if (len >= 4 && stricmp(&string[len-4], ".gat") == 0)
		len -= 4; // strip .gat extension

	len = min(len, MAP_NAME_LENGTH-1);
	safestrncpy(dest, string, len+1);
	memset(&dest[len], '\0', MAP_NAME_LENGTH-len);

	return dest;
}

/// Retrieves the map name from 'string' (adding .gat extension if not already present).
/// Result gets placed either into 'buf' or in a static local buffer.
const char* mapindex_getmapname_ext(const char* string, char* output) {
	static char buf[MAP_NAME_LENGTH_EXT];
	char* dest = (output != NULL) ? output : buf;

	size_t len;

	safestrncpy(buf,string, sizeof(buf));
	sscanf(string, "%*[^#]%*[#]%15s", buf);

	len = safestrnlen(buf, MAP_NAME_LENGTH);

	if (len == MAP_NAME_LENGTH) {
		ShowWarning("(mapindex_normalize_name) Nome do mapa '%s' muito extenso!\n", buf);
		len--;
	}
	safestrncpy(dest, buf, len+1);

	if (len < 4 || stricmp(&dest[len-4], ".gat") != 0) {
		strcpy(&dest[len], ".gat");
		len += 4; // add .gat extension
	}

	memset(&dest[len], '\0', MAP_NAME_LENGTH_EXT-len);

	return dest;
}

/// Adds a map to the specified index
/// Returns 1 if successful, 0 otherwise
int mapindex_addmap(int index, const char* name) {
	char map_name[MAP_NAME_LENGTH];

	if (index == -1){
		for (index = 1; index < mapindex->num; index++) {
			if (mapindex->list[index].name[0] == '\0')
				break;
		}
	}

	if (index < 0 || index >= MAX_MAPINDEX) {
		ShowError("(mapindex_add) Indice do mapa (%d) mapa \"%s\" fora do alcance (maximo %d)\n", index, name, MAX_MAPINDEX);
		return 0;
	}

	mapindex->getmapname(name, map_name);

	if (map_name[0] == '\0') {
		ShowError("(mapindex_add) Nao foi possivel adicionar mapas sem nome.\n");
		return 0;
	}

	if (strlen(map_name) >= MAP_NAME_LENGTH) {
		ShowError("(mapindex_add) Nome do mapa %s muito extenso. Mapas sao limitados a %d caracteres.\n", map_name, MAP_NAME_LENGTH);
		return 0;
	}

	if (mapindex_exists(index)) {
		ShowWarning("(mapindex_add) Substituindo indice %d: mapa \"%s\" -> \"%s\"\n", index, mapindex->list[index].name, map_name);
		strdb_remove(mapindex->db, mapindex->list[index].name);
	}

	safestrncpy(mapindex->list[index].name, map_name, MAP_NAME_LENGTH);
	strdb_iput(mapindex->db, map_name, index);

	if (mapindex->num <= index)
		mapindex->num = index+1;

	return index;
}

unsigned short mapindex_name2id(const char* name) {
	int i;
	char map_name[MAP_NAME_LENGTH];

	mapindex->getmapname(name, map_name);

	if( (i = strdb_iget(mapindex->db, map_name)) )
		return i;

	ShowDebug("mapindex_name2id: Mapa \"%s\" nao foi encontrado na lista do indice!\n", map_name);
	return 0;
}

const char *mapindex_id2name_sub(uint16 id, const char *file, int line, const char *func) {
	if (id >= MAX_MAPINDEX || !mapindex_exists(id)) {
		ShowDebug("mapindex_id2name: Nome requisitado para mapa nao existente [%d] em cache. %s:%s:%d\n", id,file,func,line);
		return mapindex->list[0].name; // dummy empty string so that the callee doesn't crash
	}
	return mapindex->list[id].name;
}

int mapindex_init(void) {
	int i = 0;

	mapindex->db = strdb_alloc(DB_OPT_DUP_KEY, MAP_NAME_LENGTH);

	for (; i < ARRAYLENGTH(map_list); i++) {
		if (map_list[i] == NULL)
			continue;

		mapindex->addmap((i + 1), map_list[i]);
	}

	mapindex->check_default();
	return i;
}

bool mapindex_check_default(void)
{
	if (!strdb_iget(mapindex->db, mapindex->default_map)) {
		ShowError("mapindex_init: MAP_DEFAULT '%s' nao foi encontrado em cache! Modifique o valor de MAP_DEFAULT em mapindex.h!!!\n", mapindex->default_map);
		return false;
	}
	return true;
}

void mapindex_removemap(int index){
	strdb_remove(mapindex->db, mapindex->list[index].name);
	mapindex->list[index].name[0] = '\0';
}

void mapindex_final(void) {
	db_destroy(mapindex->db);
}

void mapindex_defaults(void) {
	mapindex = &mapindex_s;

	/* TODO: place it in inter-server.conf? */
	snprintf(mapindex->config_file, sizeof(mapindex->config_file), "%s","db/map_index.txt");
	/* */
	mapindex->db = NULL;
	mapindex->num = 0;
	mapindex->default_map = MAP_DEFAULT;
	mapindex->default_x = MAP_DEFAULT_X;
	mapindex->default_y = MAP_DEFAULT_Y;
	memset (&mapindex->list, 0, sizeof (mapindex->list));

	/* */
	mapindex->init = mapindex_init;
	mapindex->final = mapindex_final;
	/* */
	mapindex->addmap = mapindex_addmap;
	mapindex->removemap = mapindex_removemap;
	mapindex->getmapname = mapindex_getmapname;
	mapindex->getmapname_ext = mapindex_getmapname_ext;
	mapindex->name2id = mapindex_name2id;
	mapindex->id2name = mapindex_id2name_sub;
	mapindex->check_default = mapindex_check_default;
}