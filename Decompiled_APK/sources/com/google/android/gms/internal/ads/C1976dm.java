package com.google.android.gms.internal.ads;

import android.content.Context;
import android.net.NetworkInfo;
import android.telephony.TelephonyManager;
import android.util.SparseArray;

/* renamed from: com.google.android.gms.internal.ads.dm, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C1976dm extends androidx.appcompat.app.y {
    public static final SparseArray i;
    public final Context d;
    public final androidx.camera.core.processing.e e;
    public final TelephonyManager f;
    public final C1889bm g;
    public int h;

    static {
        SparseArray sparseArray = new SparseArray();
        i = sparseArray;
        sparseArray.put(NetworkInfo.DetailedState.CONNECTED.ordinal(), EnumC2901z6.CONNECTED);
        int iOrdinal = NetworkInfo.DetailedState.AUTHENTICATING.ordinal();
        EnumC2901z6 enumC2901z6 = EnumC2901z6.CONNECTING;
        sparseArray.put(iOrdinal, enumC2901z6);
        sparseArray.put(NetworkInfo.DetailedState.CONNECTING.ordinal(), enumC2901z6);
        sparseArray.put(NetworkInfo.DetailedState.OBTAINING_IPADDR.ordinal(), enumC2901z6);
        sparseArray.put(NetworkInfo.DetailedState.DISCONNECTING.ordinal(), EnumC2901z6.DISCONNECTING);
        int iOrdinal2 = NetworkInfo.DetailedState.BLOCKED.ordinal();
        EnumC2901z6 enumC2901z62 = EnumC2901z6.DISCONNECTED;
        sparseArray.put(iOrdinal2, enumC2901z62);
        sparseArray.put(NetworkInfo.DetailedState.DISCONNECTED.ordinal(), enumC2901z62);
        sparseArray.put(NetworkInfo.DetailedState.FAILED.ordinal(), enumC2901z62);
        sparseArray.put(NetworkInfo.DetailedState.IDLE.ordinal(), enumC2901z62);
        sparseArray.put(NetworkInfo.DetailedState.SCANNING.ordinal(), enumC2901z62);
        sparseArray.put(NetworkInfo.DetailedState.SUSPENDED.ordinal(), EnumC2901z6.SUSPENDED);
        sparseArray.put(NetworkInfo.DetailedState.CAPTIVE_PORTAL_CHECK.ordinal(), enumC2901z6);
        sparseArray.put(NetworkInfo.DetailedState.VERIFYING_POOR_LINK.ordinal(), enumC2901z6);
    }

    public C1976dm(Context context, androidx.camera.core.processing.e eVar, C1889bm c1889bm, Fi fi, com.google.android.gms.ads.internal.util.C c) {
        super(fi, c);
        this.d = context;
        this.e = eVar;
        this.g = c1889bm;
        this.f = (TelephonyManager) context.getSystemService("phone");
    }
}
