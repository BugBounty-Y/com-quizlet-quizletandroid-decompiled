package com.squareup.moshi;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.LinkedHashSet;

/* renamed from: com.squareup.moshi.g, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4852g extends l {
    public static final com.quizlet.remote.model.selectedterm.c c = new com.quizlet.remote.model.selectedterm.c(3);
    public final l a;
    public final /* synthetic */ int b;

    public C4852g(l lVar, int i) {
        this.b = i;
        this.a = lVar;
    }

    @Override // com.squareup.moshi.l
    public final Object a(p pVar) {
        switch (this.b) {
            case 0:
                Collection collectionH = h();
                pVar.a();
                while (pVar.l()) {
                    ((ArrayList) collectionH).add(this.a.a(pVar));
                }
                pVar.f();
                return collectionH;
            default:
                Collection collectionH2 = h();
                pVar.a();
                while (pVar.l()) {
                    collectionH2.add(this.a.a(pVar));
                }
                pVar.f();
                return collectionH2;
        }
    }

    @Override // com.squareup.moshi.l
    public final void g(w wVar, Object obj) {
        switch (this.b) {
            case 0:
                wVar.a();
                Iterator it2 = ((Collection) obj).iterator();
                while (it2.hasNext()) {
                    this.a.g(wVar, it2.next());
                }
                ((s) wVar).Q(1, ']', 2);
                break;
            default:
                wVar.a();
                Iterator it3 = ((Collection) obj).iterator();
                while (it3.hasNext()) {
                    this.a.g(wVar, it3.next());
                }
                ((s) wVar).Q(1, ']', 2);
                break;
        }
    }

    public final Collection h() {
        switch (this.b) {
            case 0:
                return new ArrayList();
            default:
                return new LinkedHashSet();
        }
    }

    public final String toString() {
        return this.a + ".collection()";
    }
}
