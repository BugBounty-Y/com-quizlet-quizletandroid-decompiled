package com.google.firebase.perf.session;

import android.os.Parcel;
import android.os.Parcelable;
import assistantMode.utils.studiableMetadata.b;
import com.google.android.gms.fido.fido2.api.common.i;
import com.google.firebase.perf.config.o;
import com.google.firebase.perf.util.Timer;
import com.google.firebase.perf.util.d;
import com.google.firebase.perf.v1.y;
import com.google.firebase.perf.v1.z;
import java.util.List;
import java.util.concurrent.TimeUnit;

/* loaded from: classes2.dex */
public class PerfSession implements Parcelable {
    public static final Parcelable.Creator<PerfSession> CREATOR = new i(27);
    public final String a;
    public final Timer b;
    public boolean c;

    public PerfSession(String str, b bVar) {
        this.c = false;
        this.a = str;
        this.b = new Timer();
    }

    public static z[] b(List list) {
        if (list.isEmpty()) {
            return null;
        }
        z[] zVarArr = new z[list.size()];
        z zVarA = ((PerfSession) list.get(0)).a();
        boolean z = false;
        for (int i = 1; i < list.size(); i++) {
            z zVarA2 = ((PerfSession) list.get(i)).a();
            if (z || !((PerfSession) list.get(i)).c) {
                zVarArr[i] = zVarA2;
            } else {
                zVarArr[0] = zVarA2;
                zVarArr[i] = zVarA;
                z = true;
            }
        }
        if (!z) {
            zVarArr[0] = zVarA;
        }
        return zVarArr;
    }

    /* JADX WARN: Removed duplicated region for block: B:18:0x0056  */
    /* JADX WARN: Removed duplicated region for block: B:37:0x00d0  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static com.google.firebase.perf.session.PerfSession c(java.lang.String r9) {
        /*
            java.lang.String r0 = "-"
            java.lang.String r1 = ""
            java.lang.String r9 = r9.replace(r0, r1)
            com.google.firebase.perf.session.PerfSession r0 = new com.google.firebase.perf.session.PerfSession
            assistantMode.utils.studiableMetadata.b r1 = new assistantMode.utils.studiableMetadata.b
            r2 = 19
            r1.<init>(r2)
            r0.<init>(r9, r1)
            com.google.firebase.perf.config.a r9 = com.google.firebase.perf.config.a.e()
            boolean r1 = r9.o()
            if (r1 == 0) goto Ld0
            double r1 = java.lang.Math.random()
            java.lang.Class<com.google.firebase.perf.config.r> r3 = com.google.firebase.perf.config.r.class
            monitor-enter(r3)
            com.google.firebase.perf.config.r r4 = com.google.firebase.perf.config.r.b     // Catch: java.lang.Throwable -> L31
            if (r4 != 0) goto L34
            com.google.firebase.perf.config.r r4 = new com.google.firebase.perf.config.r     // Catch: java.lang.Throwable -> L31
            r4.<init>()     // Catch: java.lang.Throwable -> L31
            com.google.firebase.perf.config.r.b = r4     // Catch: java.lang.Throwable -> L31
            goto L34
        L31:
            r9 = move-exception
            goto Lce
        L34:
            com.google.firebase.perf.config.r r4 = com.google.firebase.perf.config.r.b     // Catch: java.lang.Throwable -> L31
            monitor-exit(r3)
            com.google.firebase.perf.util.d r3 = r9.i(r4)
            boolean r5 = r3.b()
            if (r5 == 0) goto L56
            java.lang.Object r3 = r3.a()
            java.lang.Double r3 = (java.lang.Double) r3
            double r5 = r3.doubleValue()
            r7 = 4636737291354636288(0x4059000000000000, double:100.0)
            double r5 = r5 / r7
            boolean r3 = com.google.firebase.perf.config.a.p(r5)
            if (r3 == 0) goto L56
            goto Lc8
        L56:
            com.google.firebase.perf.config.RemoteConfigManager r3 = r9.a
            java.lang.String r5 = "fpr_vc_session_sampling_rate"
            com.google.firebase.perf.util.d r3 = r3.getDouble(r5)
            boolean r5 = r3.b()
            if (r5 == 0) goto L90
            java.lang.Object r5 = r3.a()
            java.lang.Double r5 = (java.lang.Double) r5
            double r5 = r5.doubleValue()
            boolean r5 = com.google.firebase.perf.config.a.p(r5)
            if (r5 == 0) goto L90
            com.google.firebase.perf.config.v r9 = r9.c
            java.lang.String r4 = "com.google.firebase.perf.SessionSamplingRate"
            java.lang.Object r5 = r3.a()
            java.lang.Double r5 = (java.lang.Double) r5
            double r5 = r5.doubleValue()
            r9.e(r4, r5)
            java.lang.Object r9 = r3.a()
            java.lang.Double r9 = (java.lang.Double) r9
            double r5 = r9.doubleValue()
            goto Lc8
        L90:
            com.google.firebase.perf.util.d r3 = r9.b(r4)
            boolean r4 = r3.b()
            if (r4 == 0) goto Lb5
            java.lang.Object r4 = r3.a()
            java.lang.Double r4 = (java.lang.Double) r4
            double r4 = r4.doubleValue()
            boolean r4 = com.google.firebase.perf.config.a.p(r4)
            if (r4 == 0) goto Lb5
            java.lang.Object r9 = r3.a()
            java.lang.Double r9 = (java.lang.Double) r9
            double r5 = r9.doubleValue()
            goto Lc8
        Lb5:
            com.google.firebase.perf.config.RemoteConfigManager r9 = r9.a
            boolean r9 = r9.isLastFetchFailed()
            if (r9 == 0) goto Lc3
            r5 = 4532020583610935537(0x3ee4f8b588e368f1, double:1.0E-5)
            goto Lc8
        Lc3:
            r5 = 4576918229304087675(0x3f847ae147ae147b, double:0.01)
        Lc8:
            int r9 = (r1 > r5 ? 1 : (r1 == r5 ? 0 : -1))
            if (r9 >= 0) goto Ld0
            r9 = 1
            goto Ld1
        Lce:
            monitor-exit(r3)     // Catch: java.lang.Throwable -> L31
            throw r9
        Ld0:
            r9 = 0
        Ld1:
            r0.c = r9
            return r0
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.firebase.perf.session.PerfSession.c(java.lang.String):com.google.firebase.perf.session.PerfSession");
    }

    public final z a() {
        y yVarA = z.A();
        yVarA.k();
        z.w((z) yVarA.b, this.a);
        if (this.c) {
            yVarA.k();
            z.x((z) yVarA.b);
        }
        return (z) yVarA.h();
    }

    public final boolean d() {
        o oVar;
        long jLongValue;
        long minutes = TimeUnit.MICROSECONDS.toMinutes(this.b.a());
        com.google.firebase.perf.config.a aVarE = com.google.firebase.perf.config.a.e();
        aVarE.getClass();
        synchronized (o.class) {
            try {
                if (o.b == null) {
                    o.b = new o();
                }
                oVar = o.b;
            } catch (Throwable th) {
                throw th;
            }
        }
        d dVarJ = aVarE.j(oVar);
        if (!dVarJ.b() || ((Long) dVarJ.a()).longValue() <= 0) {
            d dVar = aVarE.a.getLong("fpr_session_max_duration_min");
            if (!dVar.b() || ((Long) dVar.a()).longValue() <= 0) {
                d dVarC = aVarE.c(oVar);
                jLongValue = (!dVarC.b() || ((Long) dVarC.a()).longValue() <= 0) ? 240L : ((Long) dVarC.a()).longValue();
            } else {
                aVarE.c.d(((Long) dVar.a()).longValue(), "com.google.firebase.perf.SessionsMaxDurationMinutes");
                jLongValue = ((Long) dVar.a()).longValue();
            }
        } else {
            jLongValue = ((Long) dVarJ.a()).longValue();
        }
        return minutes > jLongValue;
    }

    @Override // android.os.Parcelable
    public final int describeContents() {
        return 0;
    }

    @Override // android.os.Parcelable
    public final void writeToParcel(Parcel parcel, int i) {
        parcel.writeString(this.a);
        parcel.writeByte(this.c ? (byte) 1 : (byte) 0);
        parcel.writeParcelable(this.b, 0);
    }

    public PerfSession(Parcel parcel) {
        this.c = false;
        this.a = parcel.readString();
        this.c = parcel.readByte() != 0;
        this.b = (Timer) parcel.readParcelable(Timer.class.getClassLoader());
    }
}
