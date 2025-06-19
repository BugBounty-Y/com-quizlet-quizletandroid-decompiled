package com.google.firebase.perf.v1;

import com.google.protobuf.InterfaceC4030y;

/* renamed from: com.google.firebase.perf.v1.h, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C3978h implements InterfaceC4030y {
    public static final C3978h b = new C3978h(0);
    public static final C3978h c = new C3978h(1);
    public static final C3978h d = new C3978h(2);
    public static final C3978h e = new C3978h(3);
    public static final C3978h f = new C3978h(4);
    public final /* synthetic */ int a;

    public /* synthetic */ C3978h(int i) {
        this.a = i;
    }

    @Override // com.google.protobuf.InterfaceC4030y
    public final boolean a(int i) {
        switch (this.a) {
            case 0:
                if ((i != 0 ? i != 1 ? i != 2 ? i != 3 ? null : i.FOREGROUND_BACKGROUND : i.BACKGROUND : i.FOREGROUND : i.APPLICATION_PROCESS_STATE_UNKNOWN) != null) {
                }
                break;
            case 1:
                if (r.b(i) != null) {
                }
                break;
            case 2:
                if ((i != 0 ? i != 1 ? null : s.GENERIC_CLIENT_ERROR : s.NETWORK_CLIENT_ERROR_REASON_UNKNOWN) != null) {
                }
                break;
            case 3:
                if ((i != 0 ? i != 1 ? null : A.GAUGES_AND_SYSTEM_EVENTS : A.SESSION_VERBOSITY_NONE) != null) {
                }
                break;
            default:
                if ((i != 0 ? i != 1 ? null : G.FL_LEGACY_V1 : G.SOURCE_UNKNOWN) != null) {
                }
                break;
        }
        return true;
    }
}
