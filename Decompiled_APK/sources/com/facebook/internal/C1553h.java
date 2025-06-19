package com.facebook.internal;

import android.content.Intent;
import java.util.HashMap;

/* renamed from: com.facebook.internal.h, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1553h implements com.facebook.j {
    public static final com.google.mlkit.common.internal.model.a b = new com.google.mlkit.common.internal.model.a(8);
    public static final HashMap c = new HashMap();
    public final HashMap a = new HashMap();

    public final boolean a(int i, int i2, Intent intent) {
        InterfaceC1552g interfaceC1552g;
        InterfaceC1552g interfaceC1552g2 = (InterfaceC1552g) this.a.get(Integer.valueOf(i));
        if (interfaceC1552g2 != null) {
            interfaceC1552g2.a(i2, intent);
            return true;
        }
        synchronized (b) {
            interfaceC1552g = (InterfaceC1552g) c.get(Integer.valueOf(i));
        }
        if (interfaceC1552g == null) {
            return false;
        }
        interfaceC1552g.a(i2, intent);
        return true;
    }
}
