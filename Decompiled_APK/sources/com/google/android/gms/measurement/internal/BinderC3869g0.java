package com.google.android.gms.measurement.internal;

import android.content.Context;
import android.os.Binder;
import android.os.Bundle;
import android.os.IBinder;
import android.os.IInterface;
import android.os.Parcel;
import android.os.RemoteException;
import android.text.TextUtils;
import androidx.appcompat.view.menu.RunnableC0069f;
import com.comscore.streaming.EventType;
import com.google.android.gms.internal.ads.RunnableC1788Vd;
import com.google.android.gms.internal.measurement.AbstractBinderC3076x;
import com.google.android.gms.internal.measurement.AbstractC3081y;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

/* renamed from: com.google.android.gms.measurement.internal.g0, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class BinderC3869g0 extends AbstractBinderC3076x implements InterfaceC3897v {
    public final r1 a;
    public Boolean b;
    public String c;

    public BinderC3869g0(r1 r1Var) {
        super("com.google.android.gms.measurement.internal.IMeasurementService");
        com.google.android.gms.common.internal.u.h(r1Var);
        this.a = r1Var;
        this.c = null;
    }

    @Override // com.google.android.gms.measurement.internal.InterfaceC3897v
    public final void C1(zzr zzrVar) {
        com.google.android.gms.common.internal.u.e(zzrVar.a);
        com.google.android.gms.common.internal.u.h(zzrVar.u);
        X(new RunnableC3859b0(this, zzrVar, 0));
    }

    @Override // com.google.android.gms.measurement.internal.InterfaceC3897v
    public final void C3(zzr zzrVar) {
        L2(zzrVar);
        f0(new RunnableC3859b0(this, zzrVar, 1));
    }

    @Override // com.google.android.gms.measurement.internal.InterfaceC3897v
    public final void E3(zzr zzrVar, zzag zzagVar) {
        if (this.a.h0().f0(null, AbstractC3893t.P0)) {
            L2(zzrVar);
            f0(new androidx.core.provider.k(this, zzrVar, zzagVar, 13));
        }
    }

    public final void L2(zzr zzrVar) {
        com.google.android.gms.common.internal.u.h(zzrVar);
        String str = zzrVar.a;
        com.google.android.gms.common.internal.u.e(str);
        f3(str, false);
        this.a.e().A0(zzrVar.b, zzrVar.p);
    }

    @Override // com.google.android.gms.measurement.internal.InterfaceC3897v
    public final void M2(zzr zzrVar, zzpc zzpcVar, InterfaceC3905z interfaceC3905z) {
        r1 r1Var = this.a;
        if (r1Var.h0().f0(null, AbstractC3893t.P0)) {
            L2(zzrVar);
            String str = zzrVar.a;
            com.google.android.gms.common.internal.u.h(str);
            r1Var.i().c0(new RunnableC0069f(14, this, str, zzpcVar, interfaceC3905z, false));
            return;
        }
        try {
            interfaceC3905z.S1(new zzpe(Collections.EMPTY_LIST));
            r1Var.c().o.f("[sgtm] Client upload is not enabled on the service side.");
        } catch (RemoteException e) {
            r1Var.c().j.g("[sgtm] UploadBatchesCallback failed.", e);
        }
    }

    @Override // com.google.android.gms.measurement.internal.InterfaceC3897v
    public final ArrayList N0(zzr zzrVar, boolean z) {
        L2(zzrVar);
        String str = zzrVar.a;
        com.google.android.gms.common.internal.u.h(str);
        r1 r1Var = this.a;
        try {
            List<v1> list = (List) r1Var.i().Y(new com.google.android.gms.ads.internal.util.y(this, false, str, 4)).get();
            ArrayList arrayList = new ArrayList(list.size());
            for (v1 v1Var : list) {
                if (z || !x1.L0(v1Var.c)) {
                    arrayList.add(new zzqb(v1Var));
                }
            }
            return arrayList;
        } catch (InterruptedException e) {
            e = e;
            I iC = r1Var.c();
            iC.g.h("Failed to get user properties. appId", I.a0(str), e);
            return null;
        } catch (ExecutionException e2) {
            e = e2;
            I iC2 = r1Var.c();
            iC2.g.h("Failed to get user properties. appId", I.a0(str), e);
            return null;
        }
    }

    @Override // com.google.android.gms.measurement.internal.InterfaceC3897v
    public final List P0(String str, String str2, boolean z, zzr zzrVar) {
        L2(zzrVar);
        String str3 = zzrVar.a;
        com.google.android.gms.common.internal.u.h(str3);
        r1 r1Var = this.a;
        try {
            List<v1> list = (List) r1Var.i().Y(new CallableC3865e0(this, str3, str, str2, 0)).get();
            ArrayList arrayList = new ArrayList(list.size());
            for (v1 v1Var : list) {
                if (z || !x1.L0(v1Var.c)) {
                    arrayList.add(new zzqb(v1Var));
                }
            }
            return arrayList;
        } catch (InterruptedException e) {
            e = e;
            Object obj = e;
            I iC = r1Var.c();
            iC.g.h("Failed to query user properties. appId", I.a0(str3), obj);
            return Collections.EMPTY_LIST;
        } catch (ExecutionException e2) {
            e = e2;
            Object obj2 = e;
            I iC2 = r1Var.c();
            iC2.g.h("Failed to query user properties. appId", I.a0(str3), obj2);
            return Collections.EMPTY_LIST;
        }
    }

    @Override // com.google.android.gms.measurement.internal.InterfaceC3897v
    public final byte[] P2(zzbh zzbhVar, String str) {
        com.google.android.gms.common.internal.u.e(str);
        com.google.android.gms.common.internal.u.h(zzbhVar);
        f3(str, true);
        r1 r1Var = this.a;
        I iC = r1Var.c();
        Y y = r1Var.l;
        D d = y.m;
        String str2 = zzbhVar.a;
        iC.n.g("Log and bundle. event", d.d(str2));
        ((com.google.android.gms.common.util.b) r1Var.f()).getClass();
        long jNanoTime = System.nanoTime() / 1000000;
        try {
            byte[] bArr = (byte[]) r1Var.i().Z(new androidx.camera.core.impl.utils.executor.c(this, zzbhVar, str)).get();
            if (bArr == null) {
                r1Var.c().g.g("Log and bundle returned null. appId", I.a0(str));
                bArr = new byte[0];
            }
            ((com.google.android.gms.common.util.b) r1Var.f()).getClass();
            r1Var.c().n.i("Log and bundle processed. event, size, time_ms", y.m.d(str2), Integer.valueOf(bArr.length), Long.valueOf((System.nanoTime() / 1000000) - jNanoTime));
            return bArr;
        } catch (InterruptedException e) {
            e = e;
            I iC2 = r1Var.c();
            iC2.g.i("Failed to log and bundle. appId, event, error", I.a0(str), y.m.d(str2), e);
            return null;
        } catch (ExecutionException e2) {
            e = e2;
            I iC22 = r1Var.c();
            iC22.g.i("Failed to log and bundle. appId, event, error", I.a0(str), y.m.d(str2), e);
            return null;
        }
    }

    @Override // com.google.android.gms.measurement.internal.InterfaceC3897v
    public final void Q2(zzai zzaiVar, zzr zzrVar) {
        com.google.android.gms.common.internal.u.h(zzaiVar);
        com.google.android.gms.common.internal.u.h(zzaiVar.c);
        L2(zzrVar);
        zzai zzaiVar2 = new zzai(zzaiVar);
        zzaiVar2.a = zzrVar.a;
        f0(new androidx.core.provider.k(14, this, zzaiVar2, zzrVar, false));
    }

    @Override // com.google.android.gms.measurement.internal.InterfaceC3897v
    public final zzap Q3(zzr zzrVar) {
        L2(zzrVar);
        String str = zzrVar.a;
        com.google.android.gms.common.internal.u.e(str);
        r1 r1Var = this.a;
        try {
            return (zzap) r1Var.i().Z(new com.google.android.gms.ads.internal.util.y(this, false, zzrVar, 5)).get(10000L, TimeUnit.MILLISECONDS);
        } catch (InterruptedException | ExecutionException | TimeoutException e) {
            I iC = r1Var.c();
            iC.g.h("Failed to get consent. appId", I.a0(str), e);
            return new zzap(null);
        }
    }

    @Override // com.google.android.gms.measurement.internal.InterfaceC3897v
    public final void R3(zzr zzrVar) {
        com.google.android.gms.common.internal.u.e(zzrVar.a);
        com.google.android.gms.common.internal.u.h(zzrVar.u);
        X(new RunnableC3857a0(this, zzrVar, 3));
    }

    @Override // com.google.android.gms.measurement.internal.InterfaceC3897v
    public final List T3(String str, String str2, zzr zzrVar) {
        L2(zzrVar);
        String str3 = zzrVar.a;
        com.google.android.gms.common.internal.u.h(str3);
        r1 r1Var = this.a;
        try {
            return (List) r1Var.i().Y(new CallableC3865e0(this, str3, str, str2, 2)).get();
        } catch (InterruptedException | ExecutionException e) {
            r1Var.c().g.g("Failed to get conditional user properties", e);
            return Collections.EMPTY_LIST;
        }
    }

    @Override // com.google.android.gms.internal.measurement.AbstractBinderC3076x
    public final boolean V(int i, Parcel parcel, Parcel parcel2) {
        boolean z;
        List list;
        InterfaceC3905z c3903y = null;
        InterfaceC3901x c3899w = null;
        switch (i) {
            case 1:
                zzbh zzbhVar = (zzbh) AbstractC3081y.a(parcel, zzbh.CREATOR);
                zzr zzrVar = (zzr) AbstractC3081y.a(parcel, zzr.CREATOR);
                AbstractC3081y.b(parcel);
                y0(zzbhVar, zzrVar);
                parcel2.writeNoException();
                return true;
            case 2:
                zzqb zzqbVar = (zzqb) AbstractC3081y.a(parcel, zzqb.CREATOR);
                zzr zzrVar2 = (zzr) AbstractC3081y.a(parcel, zzr.CREATOR);
                AbstractC3081y.b(parcel);
                X2(zzqbVar, zzrVar2);
                parcel2.writeNoException();
                return true;
            case 3:
            case 8:
            case EventType.WINDOW_STATE /* 22 */:
            case EventType.AUDIO /* 23 */:
            case 28:
            default:
                return false;
            case 4:
                zzr zzrVar3 = (zzr) AbstractC3081y.a(parcel, zzr.CREATOR);
                AbstractC3081y.b(parcel);
                h2(zzrVar3);
                parcel2.writeNoException();
                return true;
            case 5:
                zzbh zzbhVar2 = (zzbh) AbstractC3081y.a(parcel, zzbh.CREATOR);
                String string = parcel.readString();
                parcel.readString();
                AbstractC3081y.b(parcel);
                com.google.android.gms.common.internal.u.h(zzbhVar2);
                com.google.android.gms.common.internal.u.e(string);
                f3(string, true);
                f0(new androidx.core.provider.k(16, this, zzbhVar2, string, false));
                parcel2.writeNoException();
                return true;
            case 6:
                zzr zzrVar4 = (zzr) AbstractC3081y.a(parcel, zzr.CREATOR);
                AbstractC3081y.b(parcel);
                X1(zzrVar4);
                parcel2.writeNoException();
                return true;
            case 7:
                zzr zzrVar5 = (zzr) AbstractC3081y.a(parcel, zzr.CREATOR);
                z = parcel.readInt() != 0;
                AbstractC3081y.b(parcel);
                ArrayList arrayListN0 = N0(zzrVar5, z);
                parcel2.writeNoException();
                parcel2.writeTypedList(arrayListN0);
                return true;
            case 9:
                zzbh zzbhVar3 = (zzbh) AbstractC3081y.a(parcel, zzbh.CREATOR);
                String string2 = parcel.readString();
                AbstractC3081y.b(parcel);
                byte[] bArrP2 = P2(zzbhVar3, string2);
                parcel2.writeNoException();
                parcel2.writeByteArray(bArrP2);
                return true;
            case 10:
                long j = parcel.readLong();
                String string3 = parcel.readString();
                String string4 = parcel.readString();
                String string5 = parcel.readString();
                AbstractC3081y.b(parcel);
                Z3(j, string3, string4, string5);
                parcel2.writeNoException();
                return true;
            case 11:
                zzr zzrVar6 = (zzr) AbstractC3081y.a(parcel, zzr.CREATOR);
                AbstractC3081y.b(parcel);
                String strU2 = u2(zzrVar6);
                parcel2.writeNoException();
                parcel2.writeString(strU2);
                return true;
            case 12:
                zzai zzaiVar = (zzai) AbstractC3081y.a(parcel, zzai.CREATOR);
                zzr zzrVar7 = (zzr) AbstractC3081y.a(parcel, zzr.CREATOR);
                AbstractC3081y.b(parcel);
                Q2(zzaiVar, zzrVar7);
                parcel2.writeNoException();
                return true;
            case 13:
                zzai zzaiVar2 = (zzai) AbstractC3081y.a(parcel, zzai.CREATOR);
                AbstractC3081y.b(parcel);
                com.google.android.gms.common.internal.u.h(zzaiVar2);
                com.google.android.gms.common.internal.u.h(zzaiVar2.c);
                com.google.android.gms.common.internal.u.e(zzaiVar2.a);
                f3(zzaiVar2.a, true);
                f0(new com.google.common.util.concurrent.d(this, false, new zzai(zzaiVar2), 26));
                parcel2.writeNoException();
                return true;
            case 14:
                String string6 = parcel.readString();
                String string7 = parcel.readString();
                ClassLoader classLoader = AbstractC3081y.a;
                z = parcel.readInt() != 0;
                zzr zzrVar8 = (zzr) AbstractC3081y.a(parcel, zzr.CREATOR);
                AbstractC3081y.b(parcel);
                List listP0 = P0(string6, string7, z, zzrVar8);
                parcel2.writeNoException();
                parcel2.writeTypedList(listP0);
                return true;
            case 15:
                String string8 = parcel.readString();
                String string9 = parcel.readString();
                String string10 = parcel.readString();
                ClassLoader classLoader2 = AbstractC3081y.a;
                z = parcel.readInt() != 0;
                AbstractC3081y.b(parcel);
                List listY1 = Y1(string8, string9, string10, z);
                parcel2.writeNoException();
                parcel2.writeTypedList(listY1);
                return true;
            case 16:
                String string11 = parcel.readString();
                String string12 = parcel.readString();
                zzr zzrVar9 = (zzr) AbstractC3081y.a(parcel, zzr.CREATOR);
                AbstractC3081y.b(parcel);
                List listT3 = T3(string11, string12, zzrVar9);
                parcel2.writeNoException();
                parcel2.writeTypedList(listT3);
                return true;
            case 17:
                String string13 = parcel.readString();
                String string14 = parcel.readString();
                String string15 = parcel.readString();
                AbstractC3081y.b(parcel);
                List listZ1 = z1(string13, string14, string15);
                parcel2.writeNoException();
                parcel2.writeTypedList(listZ1);
                return true;
            case 18:
                zzr zzrVar10 = (zzr) AbstractC3081y.a(parcel, zzr.CREATOR);
                AbstractC3081y.b(parcel);
                w0(zzrVar10);
                parcel2.writeNoException();
                return true;
            case 19:
                Bundle bundle = (Bundle) AbstractC3081y.a(parcel, Bundle.CREATOR);
                zzr zzrVar11 = (zzr) AbstractC3081y.a(parcel, zzr.CREATOR);
                AbstractC3081y.b(parcel);
                g1(bundle, zzrVar11);
                parcel2.writeNoException();
                return true;
            case 20:
                zzr zzrVar12 = (zzr) AbstractC3081y.a(parcel, zzr.CREATOR);
                AbstractC3081y.b(parcel);
                R3(zzrVar12);
                parcel2.writeNoException();
                return true;
            case 21:
                zzr zzrVar13 = (zzr) AbstractC3081y.a(parcel, zzr.CREATOR);
                AbstractC3081y.b(parcel);
                zzap zzapVarQ3 = Q3(zzrVar13);
                parcel2.writeNoException();
                if (zzapVarQ3 == null) {
                    parcel2.writeInt(0);
                    return true;
                }
                parcel2.writeInt(1);
                zzapVarQ3.writeToParcel(parcel2, 1);
                return true;
            case EventType.VIDEO /* 24 */:
                zzr zzrVar14 = (zzr) AbstractC3081y.a(parcel, zzr.CREATOR);
                Bundle bundle2 = (Bundle) AbstractC3081y.a(parcel, Bundle.CREATOR);
                AbstractC3081y.b(parcel);
                L2(zzrVar14);
                String str = zzrVar14.a;
                com.google.android.gms.common.internal.u.h(str);
                r1 r1Var = this.a;
                if (r1Var.h0().f0(null, AbstractC3893t.h1)) {
                    try {
                        list = (List) r1Var.i().Z(new CallableC3867f0(this, zzrVar14, bundle2, 0)).get(10000L, TimeUnit.MILLISECONDS);
                    } catch (InterruptedException | ExecutionException | TimeoutException e) {
                        r1Var.c().g.h("Failed to get trigger URIs. appId", I.a0(str), e);
                        list = Collections.EMPTY_LIST;
                    }
                } else {
                    try {
                        list = (List) r1Var.i().Y(new CallableC3867f0(this, zzrVar14, bundle2, 1)).get();
                    } catch (InterruptedException | ExecutionException e2) {
                        r1Var.c().g.h("Failed to get trigger URIs. appId", I.a0(str), e2);
                        list = Collections.EMPTY_LIST;
                    }
                }
                parcel2.writeNoException();
                parcel2.writeTypedList(list);
                return true;
            case EventType.SUBS /* 25 */:
                zzr zzrVar15 = (zzr) AbstractC3081y.a(parcel, zzr.CREATOR);
                AbstractC3081y.b(parcel);
                k3(zzrVar15);
                parcel2.writeNoException();
                return true;
            case EventType.CDN /* 26 */:
                zzr zzrVar16 = (zzr) AbstractC3081y.a(parcel, zzr.CREATOR);
                AbstractC3081y.b(parcel);
                C1(zzrVar16);
                parcel2.writeNoException();
                return true;
            case 27:
                zzr zzrVar17 = (zzr) AbstractC3081y.a(parcel, zzr.CREATOR);
                AbstractC3081y.b(parcel);
                C3(zzrVar17);
                parcel2.writeNoException();
                return true;
            case 29:
                zzr zzrVar18 = (zzr) AbstractC3081y.a(parcel, zzr.CREATOR);
                zzpc zzpcVar = (zzpc) AbstractC3081y.a(parcel, zzpc.CREATOR);
                IBinder strongBinder = parcel.readStrongBinder();
                if (strongBinder != null) {
                    IInterface iInterfaceQueryLocalInterface = strongBinder.queryLocalInterface("com.google.android.gms.measurement.internal.IUploadBatchesCallback");
                    c3903y = iInterfaceQueryLocalInterface instanceof InterfaceC3905z ? (InterfaceC3905z) iInterfaceQueryLocalInterface : new C3903y(strongBinder, "com.google.android.gms.measurement.internal.IUploadBatchesCallback", 4);
                }
                AbstractC3081y.b(parcel);
                M2(zzrVar18, zzpcVar, c3903y);
                parcel2.writeNoException();
                return true;
            case 30:
                zzr zzrVar19 = (zzr) AbstractC3081y.a(parcel, zzr.CREATOR);
                zzag zzagVar = (zzag) AbstractC3081y.a(parcel, zzag.CREATOR);
                AbstractC3081y.b(parcel);
                E3(zzrVar19, zzagVar);
                parcel2.writeNoException();
                return true;
            case 31:
                zzr zzrVar20 = (zzr) AbstractC3081y.a(parcel, zzr.CREATOR);
                Bundle bundle3 = (Bundle) AbstractC3081y.a(parcel, Bundle.CREATOR);
                IBinder strongBinder2 = parcel.readStrongBinder();
                if (strongBinder2 != null) {
                    IInterface iInterfaceQueryLocalInterface2 = strongBinder2.queryLocalInterface("com.google.android.gms.measurement.internal.ITriggerUrisCallback");
                    c3899w = iInterfaceQueryLocalInterface2 instanceof InterfaceC3901x ? (InterfaceC3901x) iInterfaceQueryLocalInterface2 : new C3899w(strongBinder2, "com.google.android.gms.measurement.internal.ITriggerUrisCallback", 4);
                }
                AbstractC3081y.b(parcel);
                g2(zzrVar20, bundle3, c3899w);
                parcel2.writeNoException();
                return true;
        }
    }

    public final void X(Runnable runnable) {
        r1 r1Var = this.a;
        if (r1Var.i().e0()) {
            runnable.run();
        } else {
            r1Var.i().d0(runnable);
        }
    }

    @Override // com.google.android.gms.measurement.internal.InterfaceC3897v
    public final void X1(zzr zzrVar) {
        L2(zzrVar);
        f0(new RunnableC3857a0(this, zzrVar, 2));
    }

    @Override // com.google.android.gms.measurement.internal.InterfaceC3897v
    public final void X2(zzqb zzqbVar, zzr zzrVar) {
        com.google.android.gms.common.internal.u.h(zzqbVar);
        L2(zzrVar);
        f0(new androidx.core.provider.k(17, this, zzqbVar, zzrVar, false));
    }

    @Override // com.google.android.gms.measurement.internal.InterfaceC3897v
    public final List Y1(String str, String str2, String str3, boolean z) {
        f3(str, true);
        r1 r1Var = this.a;
        try {
            List<v1> list = (List) r1Var.i().Y(new CallableC3865e0(this, str, str2, str3, 1)).get();
            ArrayList arrayList = new ArrayList(list.size());
            for (v1 v1Var : list) {
                if (z || !x1.L0(v1Var.c)) {
                    arrayList.add(new zzqb(v1Var));
                }
            }
            return arrayList;
        } catch (InterruptedException e) {
            e = e;
            Object obj = e;
            I iC = r1Var.c();
            iC.g.h("Failed to get user properties as. appId", I.a0(str), obj);
            return Collections.EMPTY_LIST;
        } catch (ExecutionException e2) {
            e = e2;
            Object obj2 = e;
            I iC2 = r1Var.c();
            iC2.g.h("Failed to get user properties as. appId", I.a0(str), obj2);
            return Collections.EMPTY_LIST;
        }
    }

    @Override // com.google.android.gms.measurement.internal.InterfaceC3897v
    public final void Z3(long j, String str, String str2, String str3) {
        f0(new RunnableC3861c0(this, str2, str3, str, j, 0));
    }

    public final void f0(Runnable runnable) {
        r1 r1Var = this.a;
        if (r1Var.i().e0()) {
            runnable.run();
        } else {
            r1Var.i().c0(runnable);
        }
    }

    public final void f3(String str, boolean z) {
        boolean zIsEmpty = TextUtils.isEmpty(str);
        r1 r1Var = this.a;
        if (zIsEmpty) {
            r1Var.c().g.f("Measurement Service called without app package");
            throw new SecurityException("Measurement Service called without app package");
        }
        if (z) {
            try {
                if (this.b == null) {
                    boolean z2 = true;
                    if (!"com.google.android.gms".equals(this.c) && !com.google.android.gms.common.util.c.k(r1Var.l.a, Binder.getCallingUid()) && !com.google.android.gms.common.e.a(r1Var.l.a).b(Binder.getCallingUid())) {
                        z2 = false;
                    }
                    this.b = Boolean.valueOf(z2);
                }
                if (this.b.booleanValue()) {
                    return;
                }
            } catch (SecurityException e) {
                r1Var.c().g.g("Measurement Service called with invalid calling package. appId", I.a0(str));
                throw e;
            }
        }
        if (this.c == null) {
            Context context = r1Var.l.a;
            int callingUid = Binder.getCallingUid();
            int i = com.google.android.gms.common.d.e;
            if (com.google.android.gms.common.util.c.o(context, str, callingUid)) {
                this.c = str;
            }
        }
        if (str.equals(this.c)) {
            return;
        }
        throw new SecurityException("Unknown calling package name '" + str + "'.");
    }

    @Override // com.google.android.gms.measurement.internal.InterfaceC3897v
    public final void g1(Bundle bundle, zzr zzrVar) {
        L2(zzrVar);
        String str = zzrVar.a;
        com.google.android.gms.common.internal.u.h(str);
        f0(new RunnableC0069f(15, this, bundle, str, zzrVar, false));
    }

    @Override // com.google.android.gms.measurement.internal.InterfaceC3897v
    public final void g2(zzr zzrVar, Bundle bundle, InterfaceC3901x interfaceC3901x) {
        L2(zzrVar);
        String str = zzrVar.a;
        com.google.android.gms.common.internal.u.h(str);
        this.a.i().c0(new RunnableC1788Vd(this, zzrVar, bundle, interfaceC3901x, str));
    }

    @Override // com.google.android.gms.measurement.internal.InterfaceC3897v
    public final void h2(zzr zzrVar) {
        L2(zzrVar);
        f0(new RunnableC3857a0(this, zzrVar, 1));
    }

    @Override // com.google.android.gms.measurement.internal.InterfaceC3897v
    public final void k3(zzr zzrVar) {
        com.google.android.gms.common.internal.u.e(zzrVar.a);
        com.google.android.gms.common.internal.u.h(zzrVar.u);
        X(new RunnableC3857a0(this, zzrVar, 0));
    }

    public final void p3(zzbh zzbhVar, zzr zzrVar) {
        r1 r1Var = this.a;
        r1Var.j();
        r1Var.q(zzbhVar, zzrVar);
    }

    @Override // com.google.android.gms.measurement.internal.InterfaceC3897v
    public final String u2(zzr zzrVar) {
        L2(zzrVar);
        r1 r1Var = this.a;
        try {
            return (String) r1Var.i().Y(new com.google.android.gms.ads.internal.util.y(r1Var, false, zzrVar, 6)).get(30000L, TimeUnit.MILLISECONDS);
        } catch (InterruptedException | ExecutionException | TimeoutException e) {
            I iC = r1Var.c();
            iC.g.h("Failed to get app instance id. appId", I.a0(zzrVar.a), e);
            return null;
        }
    }

    @Override // com.google.android.gms.measurement.internal.InterfaceC3897v
    public final void w0(zzr zzrVar) {
        String str = zzrVar.a;
        com.google.android.gms.common.internal.u.e(str);
        f3(str, false);
        f0(new RunnableC3859b0(this, zzrVar, 2));
    }

    @Override // com.google.android.gms.measurement.internal.InterfaceC3897v
    public final void y0(zzbh zzbhVar, zzr zzrVar) {
        com.google.android.gms.common.internal.u.h(zzbhVar);
        L2(zzrVar);
        f0(new androidx.core.provider.k(15, this, zzbhVar, zzrVar, false));
    }

    @Override // com.google.android.gms.measurement.internal.InterfaceC3897v
    public final List z1(String str, String str2, String str3) {
        f3(str, true);
        r1 r1Var = this.a;
        try {
            return (List) r1Var.i().Y(new CallableC3865e0(this, str, str2, str3, 3)).get();
        } catch (InterruptedException | ExecutionException e) {
            r1Var.c().g.g("Failed to get conditional user properties as", e);
            return Collections.EMPTY_LIST;
        }
    }
}
