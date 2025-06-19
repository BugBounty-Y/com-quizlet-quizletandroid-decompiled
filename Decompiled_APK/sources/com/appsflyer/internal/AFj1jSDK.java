package com.appsflyer.internal;

import android.content.Intent;
import android.os.Parcelable;
import androidx.glance.appwidget.protobuf.Z;
import com.appsflyer.AFLogger;
import java.util.ConcurrentModificationException;
import kotlin.Metadata;
import kotlin.collections.C4933y;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.K;
import kotlin.jvm.internal.r;
import kotlin.p;
import org.jetbrains.annotations.NotNull;

/* loaded from: classes.dex */
public final class AFj1jSDK {

    @NotNull
    final Intent getCurrencyIso4217Code;

    /* JADX INFO: Add missing generic type declarations: [T] */
    @Metadata
    /* renamed from: com.appsflyer.internal.AFj1jSDK$1, reason: invalid class name */
    public static final class AnonymousClass1<T> extends r implements Function0<T> {
        private /* synthetic */ String $getCurrencyIso4217Code;

        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        public AnonymousClass1(String str) {
            super(0);
            this.$getCurrencyIso4217Code = str;
        }

        /* JADX WARN: Incorrect return type in method signature: ()TT; */
        @Override // kotlin.jvm.functions.Function0
        /* renamed from: J_, reason: merged with bridge method [inline-methods] */
        public final Parcelable invoke() {
            return AFj1jSDK.this.getCurrencyIso4217Code.getParcelableExtra(this.$getCurrencyIso4217Code);
        }
    }

    @Metadata
    /* renamed from: com.appsflyer.internal.AFj1jSDK$2, reason: invalid class name */
    public static final class AnonymousClass2 extends r implements Function0<String> {
        private /* synthetic */ String $getCurrencyIso4217Code;

        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        public AnonymousClass2(String str) {
            super(0);
            this.$getCurrencyIso4217Code = str;
        }

        @Override // kotlin.jvm.functions.Function0
        /* renamed from: getMediationNetwork, reason: merged with bridge method [inline-methods] */
        public final String invoke() {
            return AFj1jSDK.this.getCurrencyIso4217Code.getStringExtra(this.$getCurrencyIso4217Code);
        }
    }

    @Metadata
    /* renamed from: com.appsflyer.internal.AFj1jSDK$3, reason: invalid class name */
    public static final class AnonymousClass3 extends r implements Function0<Intent> {
        private /* synthetic */ String $getMonetizationNetwork;
        private /* synthetic */ long $getRevenue;

        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        public AnonymousClass3(String str, long j) {
            super(0);
            this.$getMonetizationNetwork = str;
            this.$getRevenue = j;
        }

        @Override // kotlin.jvm.functions.Function0
        @NotNull
        /* renamed from: K_, reason: merged with bridge method [inline-methods] */
        public final Intent invoke() {
            return AFj1jSDK.this.getCurrencyIso4217Code.putExtra(this.$getMonetizationNetwork, this.$getRevenue);
        }
    }

    @Metadata
    /* renamed from: com.appsflyer.internal.AFj1jSDK$5, reason: invalid class name */
    public static final class AnonymousClass5 extends r implements Function0<Boolean> {
        private /* synthetic */ String $getMediationNetwork;

        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        public AnonymousClass5(String str) {
            super(0);
            this.$getMediationNetwork = str;
        }

        @Override // kotlin.jvm.functions.Function0
        @NotNull
        /* renamed from: getCurrencyIso4217Code, reason: merged with bridge method [inline-methods] */
        public final Boolean invoke() {
            return Boolean.valueOf(AFj1jSDK.this.getCurrencyIso4217Code.hasExtra(this.$getMediationNetwork));
        }
    }

    public AFj1jSDK(@NotNull Intent intent) {
        Intrinsics.checkNotNullParameter(intent, "");
        this.getCurrencyIso4217Code = intent;
    }

    public final <T extends Parcelable> T H_(@NotNull String str) {
        Intrinsics.checkNotNullParameter(str, "");
        return (T) getMonetizationNetwork(new AnonymousClass1(str), android.support.v4.media.session.a.B("Error while trying to read ", str, " extra from intent"), null, true);
    }

    public final Intent I_(@NotNull String str, long j) {
        Intrinsics.checkNotNullParameter(str, "");
        return (Intent) getMonetizationNetwork(new AnonymousClass3(str, j), android.support.v4.media.session.a.B("Error while trying to write ", str, " extra to intent"), null, true);
    }

    public final boolean getMonetizationNetwork(@NotNull String str) {
        Intrinsics.checkNotNullParameter(str, "");
        Boolean bool = (Boolean) getMonetizationNetwork(new AnonymousClass5(str), android.support.v4.media.session.a.B("Error while trying to check presence of ", str, " extra from intent"), Boolean.TRUE, true);
        if (bool != null) {
            return bool.booleanValue();
        }
        return true;
    }

    public final String getRevenue(@NotNull String str) {
        Intrinsics.checkNotNullParameter(str, "");
        return (String) getMonetizationNetwork(new AnonymousClass2(str), android.support.v4.media.session.a.B("Error while trying to read ", str, " extra from intent"), null, true);
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r2v1, types: [kotlin.q] */
    /* JADX WARN: Type inference failed for: r2v9, types: [java.lang.Object] */
    /* JADX WARN: Type inference failed for: r7v3, types: [kotlin.q] */
    /* JADX WARN: Type inference failed for: r7v4 */
    /* JADX WARN: Type inference failed for: r7v5 */
    /* JADX WARN: Type inference failed for: r7v6, types: [java.lang.Object] */
    private final <T> T getMonetizationNetwork(Function0<? extends T> function0, String str, T t, boolean z) {
        T tB;
        ?? B;
        synchronized (this.getCurrencyIso4217Code) {
            try {
                p pVar = kotlin.r.b;
                tB = function0.invoke();
            } catch (Throwable th) {
                p pVar2 = kotlin.r.b;
                tB = Z.b(th);
            }
            kotlin.reflect.c[] cVarArr = {K.a(ConcurrentModificationException.class), K.a(ArrayIndexOutOfBoundsException.class)};
            Throwable thA = kotlin.r.a(tB);
            T t2 = tB;
            if (thA != null) {
                try {
                } catch (Throwable th2) {
                    p pVar3 = kotlin.r.b;
                    B = Z.b(th2);
                }
                if (!C4933y.u(K.a(thA.getClass()), cVarArr)) {
                    throw thA;
                }
                if (z) {
                    B = getMonetizationNetwork(function0, str, t, false);
                } else {
                    AFLogger.afErrorLog(str, thA, false, false);
                    B = t;
                }
                t2 = B;
            }
            Throwable thA2 = kotlin.r.a(t2);
            if (thA2 == null) {
                t = t2;
            } else {
                AFLogger.afErrorLog(str, thA2, false, false);
            }
        }
        return t;
    }
}
