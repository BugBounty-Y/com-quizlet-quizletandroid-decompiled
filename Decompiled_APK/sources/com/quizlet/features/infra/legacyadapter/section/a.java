package com.quizlet.features.infra.legacyadapter.section;

import java.util.ArrayList;
import java.util.List;

/* loaded from: classes3.dex */
public class a {
    public final ArrayList a;

    public a() {
        this.a = new ArrayList();
    }

    public int a() {
        return this.a.size();
    }

    public Object b(int i) {
        if (i < 0) {
            return null;
        }
        ArrayList arrayList = this.a;
        if (i < arrayList.size()) {
            return arrayList.get(i);
        }
        return null;
    }

    public a(List list) {
        ArrayList arrayList = new ArrayList();
        this.a = arrayList;
        arrayList.addAll(list);
    }
}
