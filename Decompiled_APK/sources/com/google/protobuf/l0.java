package com.google.protobuf;

/* loaded from: classes2.dex */
public final class l0 extends j0 {
    @Override // com.google.protobuf.j0
    public final k0 a(Object obj) {
        AbstractC4027v abstractC4027v = (AbstractC4027v) obj;
        k0 k0Var = abstractC4027v.unknownFields;
        if (k0Var != k0.f) {
            return k0Var;
        }
        k0 k0Var2 = new k0(0, new int[8], new Object[8], true);
        abstractC4027v.unknownFields = k0Var2;
        return k0Var2;
    }
}
