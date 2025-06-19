package org.slf4j.nop;

import java.util.concurrent.ConcurrentHashMap;
import org.slf4j.helpers.d;

/* loaded from: classes3.dex */
public final class a implements org.slf4j.spi.a {
    public final d a = new d();

    public a() {
        new ConcurrentHashMap();
    }

    @Override // org.slf4j.spi.a
    public final org.slf4j.a a() {
        return this.a;
    }

    @Override // org.slf4j.spi.a
    public final String b() {
        return "2.0.99";
    }
}
