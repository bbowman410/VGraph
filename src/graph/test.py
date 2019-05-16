from vgraph import VGraph

vg = VGraph('../../vuln_src_db/vuln_patch_graph_db/ffmpeg/CVE-2011-3950/vuln/diracdec.c/graph/dirac_decode_data_unit.gpickle', '../../vuln_src_db/vuln_patch_graph_db/ffmpeg/CVE-2011-3950/patch/diracdec.c/graph/dirac_decode_data_unit.gpickle')

print vg.v_to_p
