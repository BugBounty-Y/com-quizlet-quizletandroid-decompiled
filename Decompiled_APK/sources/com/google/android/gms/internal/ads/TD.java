package com.google.android.gms.internal.ads;

import android.content.Context;
import android.util.Base64;
import java.util.HashMap;
import java.util.concurrent.ExecutorService;

/* loaded from: classes2.dex */
public final /* synthetic */ class TD implements Pk, Bt, LE, InterfaceC2491pj {
    public final /* synthetic */ int a;

    public /* synthetic */ TD(int i) {
        this.a = i;
    }

    @Override // com.google.android.gms.internal.ads.Pk
    /* renamed from: b */
    public void mo10b(Object obj) {
        switch (this.a) {
            case 0:
                break;
            case 1:
                break;
            case 2:
                break;
            case 3:
                break;
            case 4:
                break;
            case 5:
                break;
            case 6:
                break;
            case 7:
                break;
            case 8:
                break;
            case 9:
                break;
            case 10:
                break;
            case 11:
                break;
            case 12:
                break;
            case 13:
                break;
            case 14:
            case 15:
            case 16:
            case 17:
            default:
                ((ExecutorService) obj).shutdown();
                break;
            case 18:
                ((C2867yF) obj).getClass();
                break;
        }
    }

    @Override // com.google.android.gms.internal.ads.Bt
    public Object zza() {
        byte[] bArr = new byte[12];
        YD.h.nextBytes(bArr);
        return Base64.encodeToString(bArr, 10);
    }

    public TD(Context context) {
        this.a = 17;
        new Ex(context);
        HashMap map = new HashMap();
        HashMap map2 = new HashMap();
        map.clear();
        map2.clear();
    }

    @Override // com.google.android.gms.internal.ads.LE
    public int b(Object obj) {
        HashMap map = ME.a;
        String str = ((HE) obj).a;
        return (str.startsWith("OMX.google") || str.startsWith("c2.android")) ? 1 : 0;
    }
}
