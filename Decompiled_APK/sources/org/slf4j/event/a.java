package org.slf4j.event;

import java.util.concurrent.LinkedBlockingQueue;
import org.slf4j.helpers.h;

/* loaded from: classes3.dex */
public final class a extends org.slf4j.helpers.a {
    public String a;
    public h b;
    public LinkedBlockingQueue c;

    @Override // org.slf4j.b
    public final boolean a() {
        return true;
    }

    @Override // org.slf4j.b
    public final boolean b() {
        return true;
    }

    @Override // org.slf4j.b
    public final boolean d() {
        return true;
    }

    @Override // org.slf4j.b
    public final boolean e() {
        return true;
    }

    @Override // org.slf4j.b
    public final boolean g() {
        return true;
    }

    @Override // org.slf4j.b
    public final String getName() {
        return this.a;
    }

    @Override // org.slf4j.helpers.a
    public final void q(int i, Object[] objArr) {
        b bVar = new b();
        System.currentTimeMillis();
        bVar.a = i;
        bVar.b = this.b;
        Thread.currentThread().getName();
        bVar.c = objArr;
        this.c.add(bVar);
    }
}
