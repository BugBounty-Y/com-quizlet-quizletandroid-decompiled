package com.braze.managers;

import android.content.Context;
import com.braze.configuration.BrazeConfigurationProvider;
import com.braze.models.IBrazeLocation;
import com.braze.support.BrazeLogger;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.braze.managers.k, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1498k implements f0 {
    public static final C1497j d = new C1497j();
    public final C1500m a;
    public final BrazeConfigurationProvider b;
    public final com.braze.location.b c;

    public C1498k(Context context, C1500m brazeManager, BrazeConfigurationProvider appConfigurationProvider) {
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(brazeManager, "brazeManager");
        Intrinsics.checkNotNullParameter(appConfigurationProvider, "appConfigurationProvider");
        this.a = brazeManager;
        this.b = appConfigurationProvider;
        this.c = new com.braze.location.b(context, d.a(appConfigurationProvider), appConfigurationProvider);
        BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.I, (Throwable) null, false, (Function0) new D(21), 6, (Object) null);
    }

    public static final String a() {
        return "Location collection enabled via sdk configuration.";
    }

    public static final String b() {
        return "Location collection disabled via sdk configuration.";
    }

    public static final String c() {
        return "***Location API not found. Please include android-sdk-location module***";
    }

    public static final String e() {
        return "Location collection is disabled. Not logging location recorded event.";
    }

    public static final String f() {
        return "Failed to log location recorded event.";
    }

    public final boolean d() {
        if (this.b.isLocationCollectionEnabled()) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.I, (Throwable) null, false, (Function0) new D(25), 6, (Object) null);
            return false;
        }
        BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.I, (Throwable) null, false, (Function0) new D(26), 6, (Object) null);
        return true;
    }

    public final boolean g() {
        com.braze.location.b bVar = this.c;
        androidx.navigation.U locationUpdateCallback = new androidx.navigation.U(this, 4);
        bVar.getClass();
        Intrinsics.checkNotNullParameter(locationUpdateCallback, "locationUpdateCallback");
        return false;
    }

    public static final String b(IBrazeLocation iBrazeLocation) {
        return "Invoked manualSetUserLocation for " + iBrazeLocation;
    }

    public final boolean a(IBrazeLocation location) {
        C1498k c1498k;
        Intrinsics.checkNotNullParameter(location, "location");
        try {
            BrazeLogger brazeLogger = BrazeLogger.INSTANCE;
            try {
                c1498k = this;
            } catch (Exception e) {
                e = e;
                c1498k = this;
                BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) c1498k, BrazeLogger.Priority.E, (Throwable) e, false, (Function0) new D(24), 4, (Object) null);
                return false;
            }
            try {
                BrazeLogger.brazelog$default(brazeLogger, (Object) c1498k, BrazeLogger.Priority.V, (Throwable) null, false, (Function0) new D(22), 6, (Object) null);
                if (d()) {
                    BrazeLogger.brazelog$default(brazeLogger, (Object) this, BrazeLogger.Priority.I, (Throwable) null, false, (Function0) new D(23), 6, (Object) null);
                    return false;
                }
                com.braze.models.i iVarA = com.braze.models.outgoing.event.b.g.a(location);
                if (iVarA == null) {
                    return true;
                }
                c1498k = this;
                c1498k.a.a(iVarA);
                return true;
            } catch (Exception e2) {
                e = e2;
                BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) c1498k, BrazeLogger.Priority.E, (Throwable) e, false, (Function0) new D(24), 4, (Object) null);
                return false;
            }
        } catch (Exception e3) {
            e = e3;
        }
    }

    public static final Unit a(C1498k c1498k, IBrazeLocation it2) {
        Intrinsics.checkNotNullParameter(it2, "it");
        c1498k.a(it2);
        return Unit.a;
    }
}
