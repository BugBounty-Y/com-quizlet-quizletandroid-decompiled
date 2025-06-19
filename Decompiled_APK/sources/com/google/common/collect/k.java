package com.google.common.collect;

import com.j256.ormlite.stmt.query.SimpleComparison;

/* loaded from: classes2.dex */
public final class k {
    public final Object a;
    public final Object b;
    public final Object c;

    public k(Object obj, Object obj2, Object obj3) {
        this.a = obj;
        this.b = obj2;
        this.c = obj3;
    }

    public final IllegalArgumentException a() {
        StringBuilder sb = new StringBuilder("Multiple entries with same key: ");
        Object obj = this.a;
        sb.append(obj);
        sb.append(SimpleComparison.EQUAL_TO_OPERATION);
        sb.append(this.b);
        sb.append(" and ");
        sb.append(obj);
        sb.append(SimpleComparison.EQUAL_TO_OPERATION);
        sb.append(this.c);
        return new IllegalArgumentException(sb.toString());
    }
}
