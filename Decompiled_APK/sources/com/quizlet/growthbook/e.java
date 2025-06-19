package com.quizlet.growthbook;

import android.os.Build;
import com.google.firebase.perf.metrics.Trace;
import com.sdk.growthbook.GrowthBookSDK;
import com.sdk.growthbook.model.GBBoolean;
import com.sdk.growthbook.model.GBJson;
import com.sdk.growthbook.model.GBNull;
import com.sdk.growthbook.model.GBNumber;
import com.sdk.growthbook.model.GBString;
import com.sdk.growthbook.model.GBValue;
import java.io.Serializable;
import java.util.LinkedHashMap;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class e implements com.quizlet.infra.contracts.growthbook.a, com.quizlet.growthbook.contracts.a {
    public final com.quizlet.usecase.a a;
    public final dagger.internal.a b;
    public final dagger.internal.a c;
    public final String d;
    public final kotlinx.coroutines.internal.d e;
    public final com.google.firebase.perf.b f;
    public GrowthBookSDK g;
    public final LinkedHashMap h;
    public boolean i;
    public Trace j;

    public e(com.quizlet.baserecyclerview.decoration.a sdkBuilderFactory, com.quizlet.usecase.a onUserChange, dagger.internal.a enrollmentRepository, dagger.internal.a experimentEnrollmentLogger, String deviceId, kotlinx.coroutines.internal.d ioScope, com.google.firebase.perf.b firebasePerformance) {
        String osVersion = Build.VERSION.RELEASE;
        Intrinsics.checkNotNullParameter(sdkBuilderFactory, "sdkBuilderFactory");
        Intrinsics.checkNotNullParameter(onUserChange, "onUserChange");
        Intrinsics.checkNotNullParameter(enrollmentRepository, "enrollmentRepository");
        Intrinsics.checkNotNullParameter(experimentEnrollmentLogger, "experimentEnrollmentLogger");
        Intrinsics.checkNotNullParameter("9.34.3", "appVersion");
        Intrinsics.checkNotNullParameter(osVersion, "osVersion");
        Intrinsics.checkNotNullParameter(deviceId, "deviceId");
        Intrinsics.checkNotNullParameter(ioScope, "ioScope");
        Intrinsics.checkNotNullParameter(firebasePerformance, "firebasePerformance");
        this.a = onUserChange;
        this.b = enrollmentRepository;
        this.c = experimentEnrollmentLogger;
        this.d = deviceId;
        this.e = ioScope;
        this.f = firebasePerformance;
        this.h = new LinkedHashMap();
    }

    public static Serializable b(GBValue gBValue) {
        if (gBValue instanceof GBBoolean) {
            return Boolean.valueOf(((GBBoolean) gBValue).getValue());
        }
        if (gBValue instanceof GBString) {
            return ((GBString) gBValue).getValue();
        }
        if (gBValue instanceof GBNumber) {
            return ((GBNumber) gBValue).getValue();
        }
        if ((gBValue instanceof GBJson) || gBValue.equals(GBValue.Unknown.INSTANCE)) {
            return null;
        }
        gBValue.equals(GBNull.INSTANCE);
        return null;
    }

    public final Serializable a(String configurationName) {
        Intrinsics.checkNotNullParameter(configurationName, "configurationName");
        if (!this.i) {
            timber.log.c.a.p(new QGrowthBookException("GrowthBook may be stale when evaluating configuration: ".concat(configurationName)));
        }
        GrowthBookSDK growthBookSDK = this.g;
        if (growthBookSDK == null) {
            Intrinsics.m("growthBookSDK");
            throw null;
        }
        if (growthBookSDK.getForcedFeatures().containsKey(configurationName)) {
            GrowthBookSDK growthBookSDK2 = this.g;
            if (growthBookSDK2 == null) {
                Intrinsics.m("growthBookSDK");
                throw null;
            }
            GBValue gBValue = growthBookSDK2.getForcedFeatures().get(configurationName);
            Serializable serializableB = gBValue != null ? b(gBValue) : null;
            if (serializableB != null) {
                return serializableB;
            }
        } else {
            GrowthBookSDK growthBookSDK3 = this.g;
            if (growthBookSDK3 == null) {
                Intrinsics.m("growthBookSDK");
                throw null;
            }
            GBValue gbValue = growthBookSDK3.feature(configurationName).getGbValue();
            Serializable serializableB2 = gbValue != null ? b(gbValue) : null;
            if (serializableB2 != null) {
                return serializableB2;
            }
        }
        return null;
    }
}
