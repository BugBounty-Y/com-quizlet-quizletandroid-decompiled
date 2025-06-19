package com.android.billingclient.api;

import android.app.Activity;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.pm.ResolveInfo;
import android.content.pm.ServiceInfo;
import androidx.appcompat.app.Q;
import com.google.android.gms.internal.play_billing.AbstractC3819n0;
import com.google.android.gms.internal.play_billing.C0;
import com.google.android.gms.internal.play_billing.C3811k1;
import com.google.android.gms.internal.play_billing.C3836t0;
import com.google.android.gms.internal.play_billing.C3854z0;
import com.google.android.gms.internal.play_billing.D0;
import com.google.android.gms.internal.play_billing.E0;
import com.google.android.gms.internal.play_billing.EnumC3828q0;
import com.google.android.gms.internal.play_billing.InterfaceC3800h;
import com.google.android.gms.internal.play_billing.InterfaceExecutorServiceC3848x0;
import com.google.android.gms.internal.play_billing.InterfaceFutureC3845w0;
import com.google.android.gms.internal.play_billing.InterfaceScheduledExecutorServiceC3851y0;
import com.google.android.gms.internal.play_billing.K1;
import com.google.android.gms.internal.play_billing.M1;
import com.google.android.gms.internal.play_billing.RunnableC3833s0;
import com.google.android.gms.internal.play_billing.Z0;
import com.google.android.gms.internal.play_billing.l2;
import com.google.android.gms.internal.play_billing.m2;
import com.google.android.gms.internal.play_billing.n2;
import com.google.android.gms.internal.play_billing.o2;
import com.google.android.gms.internal.play_billing.p2;
import com.onetrust.otpublishers.headless.Public.OTUIDisplayReason.OTUIDisplayReasonCode;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.function.Consumer;

/* loaded from: classes.dex */
public final class v extends C1473b {
    public final Context F;
    public volatile int G;
    public volatile InterfaceC3800h H;
    public volatile u I;
    public volatile InterfaceScheduledExecutorServiceC3851y0 J;

    public v(com.quizlet.shared.usecase.folderstudymaterials.b bVar, Context context) {
        super(bVar, context);
        this.G = 0;
        this.F = context;
    }

    public final /* synthetic */ void B(C1472a c1472a, com.google.android.material.search.a aVar) {
        super.a(c1472a, aVar);
    }

    public final /* synthetic */ void C(Q q, com.quizlet.billing.manager.a aVar) {
        super.f(q, aVar);
    }

    public final synchronized boolean D() {
        if (this.G == 2 && this.H != null) {
            if (this.I != null) {
                return true;
            }
        }
        return false;
    }

    public final InterfaceFutureC3845w0 E(int i) {
        if (!D()) {
            AbstractC3819n0.f("BillingClientTesting", "Billing Override Service is not ready.");
            F(OTUIDisplayReasonCode.UIShownCode.BANNER_SHOWN_SERVICE_SPECIFIC_OFF, 28, A.a(-1, "Billing Override Service connection is disconnected."));
            return new C3836t0();
        }
        s sVar = new s(this, i, 0);
        m2 m2Var = new m2();
        m2Var.c = new p2();
        o2 o2Var = new o2(m2Var);
        m2Var.b = o2Var;
        m2Var.a = s.class;
        try {
            sVar.p(m2Var);
            m2Var.a = "billingOverrideService.getBillingOverride";
            return o2Var;
        } catch (Exception e) {
            C3811k1 c3811k1 = new C3811k1(e);
            Z0 z0 = l2.f;
            n2 n2Var = o2Var.b;
            if (z0.w(n2Var, null, c3811k1)) {
                l2.d(n2Var);
            }
            return o2Var;
        }
    }

    public final void F(int i, int i2, e eVar) {
        K1 k1B = y.b(i, i2, eVar);
        Objects.requireNonNull(k1B, "ApiFailure should not be null");
        this.g.C(k1B);
    }

    public final void G(int i, Consumer consumer, Runnable runnable) {
        InterfaceScheduledExecutorServiceC3851y0 interfaceScheduledExecutorServiceC3851y0;
        InterfaceExecutorServiceC3848x0 interfaceExecutorServiceC3848x0;
        InterfaceExecutorServiceC3848x0 c0;
        InterfaceFutureC3845w0 interfaceFutureC3845w0E = E(i);
        TimeUnit timeUnit = TimeUnit.MILLISECONDS;
        synchronized (this) {
            try {
                if (this.J == null) {
                    ScheduledExecutorService scheduledExecutorServiceNewSingleThreadScheduledExecutor = Executors.newSingleThreadScheduledExecutor();
                    this.J = scheduledExecutorServiceNewSingleThreadScheduledExecutor instanceof InterfaceScheduledExecutorServiceC3851y0 ? (InterfaceScheduledExecutorServiceC3851y0) scheduledExecutorServiceNewSingleThreadScheduledExecutor : new C0(scheduledExecutorServiceNewSingleThreadScheduledExecutor);
                }
                interfaceScheduledExecutorServiceC3851y0 = this.J;
            } finally {
            }
        }
        if (!interfaceFutureC3845w0E.isDone()) {
            E0 e0 = new E0();
            e0.h = interfaceFutureC3845w0E;
            D0 d0 = new D0();
            d0.a = e0;
            e0.i = ((C0) interfaceScheduledExecutorServiceC3851y0).schedule(d0, 28500L, timeUnit);
            interfaceFutureC3845w0E.b(d0, EnumC3828q0.a);
            interfaceFutureC3845w0E = e0;
        }
        com.google.android.gms.cloudmessaging.k kVar = new com.google.android.gms.cloudmessaging.k(this, i, consumer, runnable);
        synchronized (this) {
            try {
                if (this.D == null) {
                    ExecutorService executorServiceM = m();
                    if (executorServiceM instanceof InterfaceExecutorServiceC3848x0) {
                        c0 = (InterfaceExecutorServiceC3848x0) executorServiceM;
                    } else {
                        c0 = executorServiceM instanceof ScheduledExecutorService ? new C0((ScheduledExecutorService) executorServiceM) : new C3854z0(executorServiceM);
                    }
                    this.D = c0;
                }
                interfaceExecutorServiceC3848x0 = this.D;
            } finally {
            }
        }
        interfaceFutureC3845w0E.b(new RunnableC3833s0(interfaceFutureC3845w0E, kVar), interfaceExecutorServiceC3848x0);
    }

    @Override // com.android.billingclient.api.C1473b
    public final void a(C1472a c1472a, com.google.android.material.search.a aVar) {
        G(3, new r(aVar, 1), new androidx.core.provider.k(this, c1472a, aVar, 3));
    }

    @Override // com.android.billingclient.api.C1473b
    public final void b() {
        synchronized (this) {
            M1 m1D = y.d(27);
            Objects.requireNonNull(m1D, "ApiSuccess should not be null");
            this.g.D(m1D);
            try {
                try {
                    if (this.I != null && this.H != null) {
                        AbstractC3819n0.e("BillingClientTesting", "Unbinding from Billing Override Service.");
                        this.F.unbindService(this.I);
                        this.I = new u(this, 0);
                    }
                    this.H = null;
                    if (this.J != null) {
                        ((C3854z0) this.J).shutdownNow();
                        this.J = null;
                    }
                } catch (RuntimeException e) {
                    AbstractC3819n0.g("BillingClientTesting", "There was an exception while ending Billing Override Service connection!", e);
                }
                this.G = 3;
            } catch (Throwable th) {
                this.G = 3;
                throw th;
            }
        }
        super.b();
    }

    @Override // com.android.billingclient.api.C1473b
    public final e e(Activity activity, androidx.compose.material.ripple.r rVar) {
        int iIntValue = 0;
        try {
            iIntValue = ((Integer) E(2).get(28500L, TimeUnit.MILLISECONDS)).intValue();
        } catch (TimeoutException e) {
            F(114, 28, A.D);
            AbstractC3819n0.g("BillingClientTesting", "Asynchronous call to Billing Override Service timed out.", e);
        } catch (Exception e2) {
            if (e2 instanceof InterruptedException) {
                Thread.currentThread().interrupt();
            }
            F(OTUIDisplayReasonCode.UIShownCode.BANNER_SHOWN_SYNC_FAILED, 28, A.D);
            AbstractC3819n0.g("BillingClientTesting", "An error occurred while retrieving billing override.", e2);
        }
        if (iIntValue > 0) {
            e eVarA = A.a(iIntValue, "Billing override value was set by a license tester.");
            F(OTUIDisplayReasonCode.UIShownCode.BANNER_SHOWN_CONSENT_EXPIRED, 2, eVarA);
            A(eVarA);
            return eVarA;
        }
        try {
            return super.e(activity, rVar);
        } catch (Exception e3) {
            e eVar = A.i;
            F(115, 2, eVar);
            AbstractC3819n0.g("BillingClientTesting", "An internal error occurred.", e3);
            return eVar;
        }
    }

    @Override // com.android.billingclient.api.C1473b
    public final void f(Q q, com.quizlet.billing.manager.a aVar) {
        G(7, new r(aVar, 0), new androidx.core.provider.k(this, q, aVar, 2));
    }

    @Override // com.android.billingclient.api.C1473b
    public final void h(com.quizlet.billing.manager.f fVar) {
        synchronized (this) {
            if (D()) {
                AbstractC3819n0.e("BillingClientTesting", "Billing Override Service connection is valid. No need to re-initialize.");
                M1 m1D = y.d(26);
                Objects.requireNonNull(m1D, "ApiSuccess should not be null");
                this.g.D(m1D);
            } else {
                int i = 1;
                if (this.G == 1) {
                    AbstractC3819n0.f("BillingClientTesting", "Client is already in the process of connecting to Billing Override Service.");
                } else if (this.G == 3) {
                    AbstractC3819n0.f("BillingClientTesting", "Billing Override Service Client was already closed and can't be reused. Please create another instance.");
                    F(38, 26, A.a(-1, "Billing Override Service connection is disconnected."));
                } else {
                    this.G = 1;
                    AbstractC3819n0.e("BillingClientTesting", "Starting Billing Override Service setup.");
                    this.I = new u(this, 0);
                    Intent intent = new Intent("com.google.android.apps.play.billingtestcompanion.BillingOverrideService.BIND");
                    intent.setPackage("com.google.android.apps.play.billingtestcompanion");
                    List<ResolveInfo> listQueryIntentServices = this.F.getPackageManager().queryIntentServices(intent, 0);
                    if (listQueryIntentServices == null || listQueryIntentServices.isEmpty()) {
                        i = 41;
                    } else {
                        ServiceInfo serviceInfo = listQueryIntentServices.get(0).serviceInfo;
                        if (serviceInfo != null) {
                            String str = serviceInfo.packageName;
                            String str2 = serviceInfo.name;
                            if (!Objects.equals(str, "com.google.android.apps.play.billingtestcompanion") || str2 == null) {
                                AbstractC3819n0.f("BillingClientTesting", "The device doesn't have valid Play Billing Lab.");
                            } else {
                                ComponentName componentName = new ComponentName(str, str2);
                                Intent intent2 = new Intent(intent);
                                intent2.setComponent(componentName);
                                if (this.F.bindService(intent2, this.I, 1)) {
                                    AbstractC3819n0.e("BillingClientTesting", "Billing Override Service was bonded successfully.");
                                } else {
                                    AbstractC3819n0.f("BillingClientTesting", "Connection to Billing Override Service is blocked.");
                                }
                            }
                            i = 39;
                        }
                    }
                    this.G = 0;
                    AbstractC3819n0.e("BillingClientTesting", "Billing Override Service unavailable on device.");
                    F(i, 26, A.a(2, "Billing Override Service unavailable on device."));
                }
            }
        }
        super.h(fVar);
    }

    public v(com.quizlet.shared.usecase.folderstudymaterials.b bVar, Context context, k kVar) {
        super(bVar, context, kVar);
        this.G = 0;
        this.F = context;
    }
}
