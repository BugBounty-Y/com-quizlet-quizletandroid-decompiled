package com.google.gson;

/* loaded from: classes2.dex */
public final class h extends q {
    public final /* synthetic */ int a;

    @Override // com.google.gson.q
    public final Object a(com.google.gson.stream.a aVar) {
        switch (this.a) {
            case 0:
                if (aVar.l0() != 9) {
                    return Double.valueOf(aVar.C());
                }
                aVar.a0();
                return null;
            default:
                if (aVar.l0() != 9) {
                    return Float.valueOf((float) aVar.C());
                }
                aVar.a0();
                return null;
        }
    }
}
