package com.google.protobuf;

/* loaded from: classes2.dex */
public final class O {
    public static N a(Object obj, Object obj2) {
        N nE = (N) obj;
        N n = (N) obj2;
        if (!n.isEmpty()) {
            if (!nE.a) {
                nE = nE.e();
            }
            nE.d();
            if (!n.isEmpty()) {
                nE.putAll(n);
            }
        }
        return nE;
    }
}
