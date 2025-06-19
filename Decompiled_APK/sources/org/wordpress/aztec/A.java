package org.wordpress.aztec;

import com.quizlet.db.data.models.persisted.fields.DBDiagramShapeFields;

/* loaded from: classes3.dex */
public abstract class A {
    public static final C5148d a;

    static {
        C5148d c5148d = new C5148d();
        org.ccil.cowan.tagsoup.b bVarD = c5148d.d("iframe");
        int index = bVarD.g.getIndex("frameborder");
        org.ccil.cowan.tagsoup.a aVar = bVarD.g;
        aVar.c(index);
        aVar.c(aVar.getIndex("scrolling"));
        org.ccil.cowan.tagsoup.b bVarD2 = c5148d.d("a");
        bVarD2.g.c(bVarD2.g.getIndex(DBDiagramShapeFields.Names.SHAPE));
        org.ccil.cowan.tagsoup.b bVarD3 = c5148d.d("br");
        bVarD3.g.c(bVarD3.g.getIndex("clear"));
        a = c5148d;
    }
}
