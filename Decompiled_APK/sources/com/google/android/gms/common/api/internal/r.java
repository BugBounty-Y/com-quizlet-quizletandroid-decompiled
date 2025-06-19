package com.google.android.gms.common.api.internal;

import android.os.SystemClock;
import com.google.android.gms.common.ConnectionResult;
import com.google.android.gms.common.api.ApiException;
import com.google.android.gms.common.api.Status;
import com.google.android.gms.common.internal.AbstractC1655e;
import com.google.android.gms.common.internal.ConnectionTelemetryConfiguration;
import com.google.android.gms.common.internal.MethodInvocation;
import com.google.android.gms.common.internal.RootTelemetryConfiguration;
import com.google.android.gms.common.internal.zzj;
import com.google.android.gms.internal.ads.Ls;
import com.google.android.gms.tasks.OnCompleteListener;
import com.google.android.gms.tasks.Task;

/* loaded from: classes2.dex */
public final class r implements OnCompleteListener {
    public final C1647e a;
    public final int b;
    public final C1643a c;
    public final long d;
    public final long e;

    public r(C1647e c1647e, int i, C1643a c1643a, long j, long j2) {
        this.a = c1647e;
        this.b = i;
        this.c = c1643a;
        this.d = j;
        this.e = j2;
    }

    public static ConnectionTelemetryConfiguration a(n nVar, AbstractC1655e abstractC1655e, int i) {
        zzj zzjVar = abstractC1655e.w;
        ConnectionTelemetryConfiguration connectionTelemetryConfiguration = zzjVar == null ? null : zzjVar.d;
        if (connectionTelemetryConfiguration != null && connectionTelemetryConfiguration.b) {
            int[] iArr = connectionTelemetryConfiguration.d;
            int i2 = 0;
            if (iArr == null) {
                int[] iArr2 = connectionTelemetryConfiguration.f;
                if (iArr2 != null) {
                    while (i2 < iArr2.length) {
                        if (iArr2[i2] == i) {
                            return null;
                        }
                        i2++;
                    }
                }
            } else {
                while (i2 < iArr.length) {
                    if (iArr[i2] != i) {
                        i2++;
                    }
                }
            }
            if (nVar.l < connectionTelemetryConfiguration.e) {
                return connectionTelemetryConfiguration;
            }
        }
        return null;
    }

    @Override // com.google.android.gms.tasks.OnCompleteListener
    public final void onComplete(Task task) {
        int i;
        int i2;
        int i3;
        int i4;
        int i5;
        int i6;
        long j;
        long j2;
        C1647e c1647e = this.a;
        if (c1647e.f()) {
            RootTelemetryConfiguration rootTelemetryConfiguration = (RootTelemetryConfiguration) com.google.android.gms.common.internal.i.a().a;
            if (rootTelemetryConfiguration == null || rootTelemetryConfiguration.b) {
                n nVar = (n) c1647e.j.get(this.c);
                if (nVar != null) {
                    Object obj = nVar.b;
                    if (obj instanceof AbstractC1655e) {
                        AbstractC1655e abstractC1655e = (AbstractC1655e) obj;
                        long j3 = this.d;
                        int i7 = 0;
                        boolean z = j3 > 0;
                        int i8 = abstractC1655e.q;
                        if (rootTelemetryConfiguration != null) {
                            z &= rootTelemetryConfiguration.c;
                            boolean z2 = abstractC1655e.w != null;
                            i = rootTelemetryConfiguration.d;
                            i2 = rootTelemetryConfiguration.a;
                            if (!z2 || abstractC1655e.r()) {
                                i3 = rootTelemetryConfiguration.e;
                            } else {
                                ConnectionTelemetryConfiguration connectionTelemetryConfigurationA = a(nVar, abstractC1655e, this.b);
                                if (connectionTelemetryConfigurationA == null) {
                                    return;
                                }
                                boolean z3 = connectionTelemetryConfigurationA.c && j3 > 0;
                                i3 = connectionTelemetryConfigurationA.e;
                                z = z3;
                            }
                        } else {
                            i = 5000;
                            i2 = 0;
                            i3 = 100;
                        }
                        int iElapsedRealtime = -1;
                        if (task.l()) {
                            i5 = 0;
                        } else if (task.j()) {
                            i7 = -1;
                            i5 = 100;
                        } else {
                            Exception excG = task.g();
                            if (excG instanceof ApiException) {
                                Status status = ((ApiException) excG).a;
                                i4 = status.a;
                                ConnectionResult connectionResult = status.d;
                                if (connectionResult != null) {
                                    i5 = i4;
                                    i7 = connectionResult.b;
                                }
                            } else {
                                i4 = 101;
                            }
                            i5 = i4;
                            i7 = -1;
                        }
                        if (z) {
                            long jCurrentTimeMillis = System.currentTimeMillis();
                            i6 = i3;
                            iElapsedRealtime = (int) (SystemClock.elapsedRealtime() - this.e);
                            j2 = jCurrentTimeMillis;
                            j = j3;
                        } else {
                            i6 = i3;
                            j = 0;
                            j2 = 0;
                        }
                        s sVar = new s(new MethodInvocation(this.b, i5, i7, j, j2, null, null, i8, iElapsedRealtime), i2, i, i6);
                        Ls ls = c1647e.n;
                        ls.sendMessage(ls.obtainMessage(18, sVar));
                    }
                }
            }
        }
    }
}
