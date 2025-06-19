package com.airbnb.lottie.animation.content;

import android.graphics.Matrix;
import android.graphics.Path;
import androidx.camera.camera2.internal.AbstractC0147y;
import java.util.ArrayList;
import java.util.List;
import java.util.ListIterator;

/* loaded from: classes.dex */
public final class l implements m, j {
    public final Path a = new Path();
    public final Path b = new Path();
    public final Path c = new Path();
    public final ArrayList d = new ArrayList();
    public final com.airbnb.lottie.model.content.g e;

    public l(com.airbnb.lottie.model.content.g gVar) {
        gVar.getClass();
        this.e = gVar;
    }

    public final void a(Path.Op op) {
        Matrix matrixE;
        Matrix matrixE2;
        Path path = this.b;
        path.reset();
        Path path2 = this.a;
        path2.reset();
        ArrayList arrayList = this.d;
        for (int size = arrayList.size() - 1; size >= 1; size--) {
            m mVar = (m) arrayList.get(size);
            if (mVar instanceof d) {
                d dVar = (d) mVar;
                ArrayList arrayList2 = (ArrayList) dVar.g();
                for (int size2 = arrayList2.size() - 1; size2 >= 0; size2--) {
                    Path pathH = ((m) arrayList2.get(size2)).h();
                    com.airbnb.lottie.animation.keyframe.q qVar = dVar.l;
                    if (qVar != null) {
                        matrixE2 = qVar.e();
                    } else {
                        matrixE2 = dVar.d;
                        matrixE2.reset();
                    }
                    pathH.transform(matrixE2);
                    path.addPath(pathH);
                }
            } else {
                path.addPath(mVar.h());
            }
        }
        int i = 0;
        m mVar2 = (m) arrayList.get(0);
        if (mVar2 instanceof d) {
            d dVar2 = (d) mVar2;
            List listG = dVar2.g();
            while (true) {
                ArrayList arrayList3 = (ArrayList) listG;
                if (i >= arrayList3.size()) {
                    break;
                }
                Path pathH2 = ((m) arrayList3.get(i)).h();
                com.airbnb.lottie.animation.keyframe.q qVar2 = dVar2.l;
                if (qVar2 != null) {
                    matrixE = qVar2.e();
                } else {
                    matrixE = dVar2.d;
                    matrixE.reset();
                }
                pathH2.transform(matrixE);
                path2.addPath(pathH2);
                i++;
            }
        } else {
            path2.set(mVar2.h());
        }
        this.c.op(path2, path, op);
    }

    @Override // com.airbnb.lottie.animation.content.c
    public final void b(List list, List list2) {
        int i = 0;
        while (true) {
            ArrayList arrayList = this.d;
            if (i >= arrayList.size()) {
                return;
            }
            ((m) arrayList.get(i)).b(list, list2);
            i++;
        }
    }

    @Override // com.airbnb.lottie.animation.content.j
    public final void g(ListIterator listIterator) {
        while (listIterator.hasPrevious() && listIterator.previous() != this) {
        }
        while (listIterator.hasPrevious()) {
            c cVar = (c) listIterator.previous();
            if (cVar instanceof m) {
                this.d.add((m) cVar);
                listIterator.remove();
            }
        }
    }

    @Override // com.airbnb.lottie.animation.content.m
    public final Path h() {
        Path path = this.c;
        path.reset();
        com.airbnb.lottie.model.content.g gVar = this.e;
        if (!gVar.b) {
            int iK = AbstractC0147y.k(gVar.a);
            if (iK == 0) {
                int i = 0;
                while (true) {
                    ArrayList arrayList = this.d;
                    if (i >= arrayList.size()) {
                        break;
                    }
                    path.addPath(((m) arrayList.get(i)).h());
                    i++;
                }
            } else {
                if (iK == 1) {
                    a(Path.Op.UNION);
                    return path;
                }
                if (iK == 2) {
                    a(Path.Op.REVERSE_DIFFERENCE);
                    return path;
                }
                if (iK == 3) {
                    a(Path.Op.INTERSECT);
                    return path;
                }
                if (iK == 4) {
                    a(Path.Op.XOR);
                    return path;
                }
            }
        }
        return path;
    }
}
