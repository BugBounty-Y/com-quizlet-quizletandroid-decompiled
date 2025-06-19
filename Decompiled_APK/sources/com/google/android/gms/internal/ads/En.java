package com.google.android.gms.internal.ads;

import android.os.Parcel;
import android.os.RemoteException;
import android.os.SystemClock;
import com.google.android.gms.ads.internal.client.zze;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes2.dex */
public final class En extends AbstractBinderC2814x5 implements InterfaceC2052fb {
    public static final /* synthetic */ int e = 0;
    public final C2313ld a;
    public final JSONObject b;
    public final long c;
    public boolean d;

    public En(String str, InterfaceC1965db interfaceC1965db, C2313ld c2313ld, long j) throws JSONException {
        super("com.google.android.gms.ads.internal.mediation.client.rtb.ISignalsCallback");
        JSONObject jSONObject = new JSONObject();
        this.b = jSONObject;
        this.d = false;
        this.a = c2313ld;
        this.c = j;
        try {
            jSONObject.put("adapter_version", interfaceC1965db.f().toString());
            jSONObject.put("sdk_version", interfaceC1965db.h().toString());
            jSONObject.put("name", str);
        } catch (RemoteException | NullPointerException | JSONException unused) {
        }
    }

    @Override // com.google.android.gms.internal.ads.AbstractBinderC2814x5
    public final boolean d4(int i, Parcel parcel, Parcel parcel2) {
        if (i == 1) {
            String string = parcel.readString();
            AbstractC2857y5.b(parcel);
            synchronized (this) {
                if (!this.d) {
                    if (string == null) {
                        synchronized (this) {
                            e4(2, "Adapter returned null signals");
                        }
                    } else {
                        try {
                            JSONObject jSONObject = this.b;
                            jSONObject.put("signals", string);
                            C2601s7 c2601s7 = AbstractC2773w7.E1;
                            com.google.android.gms.ads.internal.client.r rVar = com.google.android.gms.ads.internal.client.r.d;
                            if (((Boolean) rVar.c.a(c2601s7)).booleanValue()) {
                                com.google.android.gms.ads.internal.j.C.k.getClass();
                                jSONObject.put("latency", SystemClock.elapsedRealtime() - this.c);
                            }
                            if (((Boolean) rVar.c.a(AbstractC2773w7.D1)).booleanValue()) {
                                jSONObject.put("signal_error_code", 0);
                            }
                        } catch (JSONException unused) {
                        }
                        this.a.c(this.b);
                        this.d = true;
                    }
                }
            }
        } else if (i == 2) {
            String string2 = parcel.readString();
            AbstractC2857y5.b(parcel);
            synchronized (this) {
                e4(2, string2);
            }
        } else {
            if (i != 3) {
                return false;
            }
            zze zzeVar = (zze) AbstractC2857y5.a(parcel, zze.CREATOR);
            AbstractC2857y5.b(parcel);
            synchronized (this) {
                e4(2, zzeVar.b);
            }
        }
        parcel2.writeNoException();
        return true;
    }

    public final synchronized void e4(int i, String str) {
        try {
            if (this.d) {
                return;
            }
            try {
                JSONObject jSONObject = this.b;
                jSONObject.put("signal_error", str);
                C2601s7 c2601s7 = AbstractC2773w7.E1;
                com.google.android.gms.ads.internal.client.r rVar = com.google.android.gms.ads.internal.client.r.d;
                if (((Boolean) rVar.c.a(c2601s7)).booleanValue()) {
                    com.google.android.gms.ads.internal.j.C.k.getClass();
                    jSONObject.put("latency", SystemClock.elapsedRealtime() - this.c);
                }
                if (((Boolean) rVar.c.a(AbstractC2773w7.D1)).booleanValue()) {
                    jSONObject.put("signal_error_code", i);
                }
            } catch (JSONException unused) {
            }
            this.a.c(this.b);
            this.d = true;
        } catch (Throwable th) {
            throw th;
        }
    }
}
