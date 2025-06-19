package com.google.firebase.sessions.settings;

import android.content.Context;
import android.os.Bundle;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3397u1;
import kotlin.Unit;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

/* loaded from: classes2.dex */
public final class a implements o {
    public final Bundle a;

    public a(@NotNull Context appContext) {
        Intrinsics.checkNotNullParameter(appContext, "appContext");
        Bundle bundle = appContext.getPackageManager().getApplicationInfo(appContext.getPackageName(), 128).metaData;
        this.a = bundle == null ? Bundle.EMPTY : bundle;
    }

    @Override // com.google.firebase.sessions.settings.o
    public final Boolean a() {
        Bundle bundle = this.a;
        if (bundle.containsKey("firebase_sessions_enabled")) {
            return Boolean.valueOf(bundle.getBoolean("firebase_sessions_enabled"));
        }
        return null;
    }

    @Override // com.google.firebase.sessions.settings.o
    public final kotlin.time.b b() {
        Bundle bundle = this.a;
        if (bundle.containsKey("firebase_sessions_sessions_restart_timeout")) {
            return new kotlin.time.b(AbstractC3397u1.f(bundle.getInt("firebase_sessions_sessions_restart_timeout"), kotlin.time.d.d));
        }
        return null;
    }

    @Override // com.google.firebase.sessions.settings.o
    public final Double c() {
        Bundle bundle = this.a;
        if (bundle.containsKey("firebase_sessions_sampling_rate")) {
            return Double.valueOf(bundle.getDouble("firebase_sessions_sampling_rate"));
        }
        return null;
    }

    @Override // com.google.firebase.sessions.settings.o
    public final Object d(kotlin.coroutines.h hVar) {
        return Unit.a;
    }
}
