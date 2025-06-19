package com.perimeterx.mobile_sdk.main;

import androidx.annotation.Keep;
import java.util.concurrent.TimeUnit;
import kotlin.Metadata;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import okhttp3.H;
import okhttp3.internal.b;
import okhttp3.internal.http.f;
import okhttp3.t;
import okhttp3.u;
import org.jetbrains.annotations.NotNull;

@Keep
@Metadata
/* loaded from: classes2.dex */
public final class PXTimeoutInterceptor implements u {
    private final Integer connectTimeoutMillis;
    private final Integer readTimeoutMillis;
    private final Integer writeTimeoutMillis;

    public PXTimeoutInterceptor() {
        this(null, null, null, 7, null);
    }

    private final t withTimeouts(t tVar) {
        Integer num = this.connectTimeoutMillis;
        if (num != null) {
            int iIntValue = num.intValue();
            TimeUnit unit = TimeUnit.MILLISECONDS;
            f fVar = (f) tVar;
            fVar.getClass();
            Intrinsics.checkNotNullParameter(unit, "unit");
            if (fVar.d != null) {
                throw new IllegalStateException("Timeouts can't be adjusted in a network interceptor");
            }
            tVar = f.a(fVar, 0, null, null, b.b("connectTimeout", iIntValue, unit), 0, 0, 55);
        }
        Integer num2 = this.readTimeoutMillis;
        if (num2 != null) {
            int iIntValue2 = num2.intValue();
            TimeUnit unit2 = TimeUnit.MILLISECONDS;
            f fVar2 = (f) tVar;
            fVar2.getClass();
            Intrinsics.checkNotNullParameter(unit2, "unit");
            if (fVar2.d != null) {
                throw new IllegalStateException("Timeouts can't be adjusted in a network interceptor");
            }
            tVar = f.a(fVar2, 0, null, null, 0, b.b("readTimeout", iIntValue2, unit2), 0, 47);
        }
        Integer num3 = this.writeTimeoutMillis;
        if (num3 == null) {
            return tVar;
        }
        int iIntValue3 = num3.intValue();
        TimeUnit unit3 = TimeUnit.MILLISECONDS;
        f fVar3 = (f) tVar;
        fVar3.getClass();
        Intrinsics.checkNotNullParameter(unit3, "unit");
        if (fVar3.d == null) {
            return f.a(fVar3, 0, null, null, 0, 0, b.b("writeTimeout", iIntValue3, unit3), 31);
        }
        throw new IllegalStateException("Timeouts can't be adjusted in a network interceptor");
    }

    @Override // okhttp3.u
    @NotNull
    public H intercept(@NotNull t chain) {
        Intrinsics.checkNotNullParameter(chain, "chain");
        return ((f) withTimeouts(chain)).b(((f) chain).e);
    }

    public PXTimeoutInterceptor(Integer num, Integer num2, Integer num3) {
        this.connectTimeoutMillis = num;
        this.readTimeoutMillis = num2;
        this.writeTimeoutMillis = num3;
    }

    public /* synthetic */ PXTimeoutInterceptor(Integer num, Integer num2, Integer num3, int i, DefaultConstructorMarker defaultConstructorMarker) {
        this((i & 1) != 0 ? null : num, (i & 2) != 0 ? null : num2, (i & 4) != 0 ? null : num3);
    }
}
