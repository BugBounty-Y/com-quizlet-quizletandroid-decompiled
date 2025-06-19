package com.squareup.moshi.adapters;

import com.squareup.moshi.D;
import com.squareup.moshi.G;
import com.squareup.moshi.H;
import com.squareup.moshi.internal.b;
import com.squareup.moshi.k;
import com.squareup.moshi.l;
import java.lang.reflect.Type;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

/* loaded from: classes3.dex */
public final class a implements k {
    public final Class a;
    public final String b;
    public final List c;
    public final List d;

    public a(Class cls, String str, List list, List list2) {
        this.a = cls;
        this.b = str;
        this.c = list;
        this.d = list2;
    }

    @Override // com.squareup.moshi.k
    public final l a(Type type, Set set, D d) {
        if (H.d(type) != this.a || !set.isEmpty()) {
            return null;
        }
        List list = this.d;
        ArrayList arrayList = new ArrayList(list.size());
        int size = list.size();
        for (int i = 0; i < size; i++) {
            Type type2 = (Type) list.get(i);
            d.getClass();
            arrayList.add(d.a(type2, b.a, null));
        }
        return new G(this.b, this.c, list, arrayList).e();
    }

    public final a b(Class cls, String str) {
        List list = this.c;
        if (list.contains(str)) {
            throw new IllegalArgumentException("Labels must be unique.");
        }
        ArrayList arrayList = new ArrayList(list);
        arrayList.add(str);
        ArrayList arrayList2 = new ArrayList(this.d);
        arrayList2.add(cls);
        return new a(this.a, this.b, arrayList, arrayList2);
    }
}
