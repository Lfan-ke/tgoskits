/* model_realassets - iterate the shipped real models, assert parse + counts/bbox vs golden (cell 5).
 *
 * Walks the real assets staged under MODEL_DIR and, for each, asserts it parses and yields sane geometry
 * matching the calibrated golden (vert/tri counts, bounding box). This is the integration leg: every real
 * model the carpet ships is exercised through the self-written parsers with a hard golden.
 *   - suzanne.obj  : 507 verts, 968 tris (quad fan), bbox
 *   - suzanne.stl  : 968 tris, bbox
 *   - suzanne.glb  : parses via cgltf, >=1 mesh
 *   - benchy.stl   : 16186 tris, bbox z[0,48]
 *   - bunny.ply    : 35947 verts, 69451 faces (triangulated -> 69451 tris, all faces are triangles), bbox
 * Prebuild refuses to stage without every real model, so a missing one fails the cell.
 */
#include "model_common.h"
#include "model_parse.h"

#define CGLTF_IMPLEMENTATION
#include "third_party/cgltf.h"

int main(void) {
    gate g; gate_init(&g, "MODEL_REALASSETS");
    char path[512];

    int parsed = 0;

    /* suzanne.obj */
    { mesh m; model_path(path,sizeof path,"suzanne.obj");
      if (parse_obj(path,&m)==0 && m.nv>0) { parsed++;
          gate_check(&g, m.nv==507, "suzanne.obj 507 verts");
          gate_check(&g, m.nt==968, "suzanne.obj 968 tris");
          vec3 lo,hi; mesh_bbox(&m,&lo,&hi);
          gate_check(&g, approx(hi.x-lo.x,2.734375,1e-4), "suzanne.obj width");
          mesh_free(&m);
      } else { gate_check(&g, 0, "suzanne.obj parses"); } }

    /* suzanne.stl */
    { mesh m; model_path(path,sizeof path,"suzanne.stl");
      if (parse_stl(path,&m)==0 && m.nt>0) { parsed++;
          gate_check(&g, m.nt==968, "suzanne.stl 968 tris");
          vec3 lo,hi; mesh_bbox(&m,&lo,&hi);
          gate_check(&g, approx(lo.z,-0.984375,1e-4)&&approx(hi.z,0.984375,1e-4), "suzanne.stl bbox z");
          mesh_free(&m);
      } else { gate_check(&g, 0, "suzanne.stl parses"); } }

    /* benchy.stl */
    { mesh m; model_path(path,sizeof path,"benchy.stl");
      if (parse_stl(path,&m)==0 && m.nt>0) { parsed++;
          gate_check(&g, m.nt==16186, "benchy.stl 16186 tris");
          vec3 lo,hi; mesh_bbox(&m,&lo,&hi);
          gate_check(&g, approx(lo.z,0.0,1e-3)&&approx(hi.z,48.0,1e-3), "benchy.stl bbox z[0,48]");
          mesh_free(&m);
      } else { gate_check(&g, 0, "benchy.stl parses"); } }

    /* bunny.ply (mesh: 35947 verts, 69451 triangular faces) */
    { mesh m; model_path(path,sizeof path,"bunny.ply");
      if (parse_ply(path,&m)==0 && m.nv>0) { parsed++;
          gate_check(&g, m.nv==35947, "bunny.ply 35947 verts");
          gate_check(&g, m.nt==69451, "bunny.ply 69451 tris (all faces triangular)");
          vec3 lo,hi; mesh_bbox(&m,&lo,&hi);
          gate_check(&g, approx(lo.y,0.0329874,1e-5)&&approx(hi.y,0.187321,1e-5), "bunny.ply bbox y");
          mesh_free(&m);
      } else { gate_check(&g, 0, "bunny.ply parses"); } }

    /* suzanne.glb via cgltf */
    { model_path(path,sizeof path,"suzanne.glb");
      FILE *f=fopen(path,"rb");
      if (f) { fclose(f);
          cgltf_options opt; memset(&opt,0,sizeof opt); cgltf_data *d=NULL;
          cgltf_result r=cgltf_parse_file(&opt,path,&d);
          gate_check(&g, r==cgltf_result_success && d, "suzanne.glb cgltf parse");
          if (r==cgltf_result_success && d) { parsed++;
              gate_check(&g, d->meshes_count>=1, "suzanne.glb >=1 mesh");
              cgltf_free(d);
          }
      } else { gate_check(&g, 0, "suzanne.glb present"); } }

    gate_check(&g, parsed == 5, "all 5 real assets parsed");
    fprintf(stderr, "  model_realassets: parsed %d real models under %s\n", parsed, model_dir());
    return gate_finish(&g);
}
