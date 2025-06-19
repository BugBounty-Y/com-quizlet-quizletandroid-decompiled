package com.bumptech.glide.load.engine;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/* loaded from: classes.dex */
public final class t {
    public final com.quizlet.data.repository.course.membership.c a;
    public final List b;
    public final String c;

    public t(Class cls, Class cls2, Class cls3, List list, com.quizlet.data.repository.course.membership.c cVar) {
        this.a = cVar;
        if (list.isEmpty()) {
            throw new IllegalArgumentException("Must not be empty.");
        }
        this.b = list;
        this.c = "Failed LoadPath{" + cls.getSimpleName() + "->" + cls2.getSimpleName() + "->" + cls3.getSimpleName() + "}";
    }

    public final v a(int i, int i2, com.android.billingclient.api.s sVar, com.bumptech.glide.load.h hVar, com.bumptech.glide.load.data.g gVar) {
        com.quizlet.data.repository.course.membership.c cVar = this.a;
        List list = (List) cVar.a();
        try {
            List list2 = this.b;
            int size = list2.size();
            v vVarA = null;
            for (int i3 = 0; i3 < size; i3++) {
                try {
                    vVarA = ((i) list2.get(i3)).a(i, i2, sVar, hVar, gVar);
                } catch (GlideException e) {
                    list.add(e);
                }
                if (vVarA != null) {
                    break;
                }
            }
            if (vVarA != null) {
                return vVarA;
            }
            throw new GlideException(this.c, new ArrayList(list));
        } finally {
            cVar.o(list);
        }
    }

    public final String toString() {
        return "LoadPath{decodePaths=" + Arrays.toString(this.b.toArray()) + '}';
    }
}
