package com.google.android.gms.internal.measurement;

import android.content.Context;
import android.os.Bundle;
import android.util.Log;
import com.google.android.gms.dynamite.DynamiteModule$LoadingException;
import com.google.android.gms.dynamite.descriptors.com.google.android.gms.measurement.dynamite.ModuleDescriptor;
import com.google.android.gms.measurement.internal.AbstractC3883n0;

/* loaded from: classes2.dex */
public final class X extends AbstractRunnableC2988f0 {
    public final /* synthetic */ String e;
    public final /* synthetic */ String f;
    public final /* synthetic */ Context g;
    public final /* synthetic */ Bundle h;
    public final /* synthetic */ C3008j0 i;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public X(C3008j0 c3008j0, String str, String str2, Context context, Bundle bundle) {
        super(c3008j0, true);
        this.e = str;
        this.f = str2;
        this.g = context;
        this.h = bundle;
        this.i = c3008j0;
    }

    @Override // com.google.android.gms.internal.measurement.AbstractRunnableC2988f0
    public final void a() throws ClassNotFoundException {
        boolean z;
        String str;
        String str2;
        String str3;
        try {
            C3008j0 c3008j0 = this.i;
            String str4 = this.e;
            String str5 = this.f;
            c3008j0.getClass();
            if (str5 == null || str4 == null) {
                z = false;
            } else {
                try {
                    Class.forName("com.google.firebase.analytics.FirebaseAnalytics", false, C3008j0.class.getClassLoader());
                    z = false;
                } catch (ClassNotFoundException unused) {
                    z = true;
                }
            }
            J jAsInterface = null;
            if (z) {
                str2 = str4;
                str3 = str5;
                str = c3008j0.a;
            } else {
                str = null;
                str2 = null;
                str3 = null;
            }
            Context context = this.g;
            com.google.android.gms.common.internal.u.h(context);
            try {
                jAsInterface = I.asInterface(com.google.android.gms.dynamite.c.c(context, com.google.android.gms.dynamite.c.d, ModuleDescriptor.MODULE_ID).b("com.google.android.gms.measurement.internal.AppMeasurementDynamiteService"));
            } catch (DynamiteModule$LoadingException e) {
                c3008j0.b(e, true, false);
            }
            c3008j0.i = jAsInterface;
            if (c3008j0.i == null) {
                Log.w(c3008j0.a, "Failed to connect to measurement client.");
                return;
            }
            int iA = com.google.android.gms.dynamite.c.a(context, ModuleDescriptor.MODULE_ID);
            zzdh zzdhVar = new zzdh(119002L, Math.max(iA, r2), com.google.android.gms.dynamite.c.d(context, ModuleDescriptor.MODULE_ID, false) < iA, str, str2, str3, this.h, AbstractC3883n0.b(context));
            J j = c3008j0.i;
            com.google.android.gms.common.internal.u.h(j);
            j.initialize(new com.google.android.gms.dynamic.b(context), zzdhVar, this.a);
        } catch (Exception e2) {
            this.i.b(e2, true, false);
        }
    }
}
