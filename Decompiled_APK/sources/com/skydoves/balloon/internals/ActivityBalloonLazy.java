package com.skydoves.balloon.internals;

import android.content.Context;
import androidx.lifecycle.J;
import com.skydoves.balloon.Balloon;
import com.skydoves.balloon.Balloon.Factory;
import java.io.Serializable;
import kotlin.Metadata;
import kotlin.jvm.a;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.z;
import kotlin.k;
import kotlin.reflect.c;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class ActivityBalloonLazy<T extends Balloon.Factory> implements k, Serializable {
    private Balloon cached;

    @NotNull
    private final Context context;

    @NotNull
    private final c factory;

    @NotNull
    private final J lifecycleOwner;

    public ActivityBalloonLazy(@NotNull Context context, @NotNull J lifecycleOwner, @NotNull c factory) {
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(lifecycleOwner, "lifecycleOwner");
        Intrinsics.checkNotNullParameter(factory, "factory");
        this.context = context;
        this.lifecycleOwner = lifecycleOwner;
        this.factory = factory;
    }

    @Override // kotlin.k
    public boolean isInitialized() {
        return this.cached != null;
    }

    @NotNull
    public String toString() {
        return isInitialized() ? getValue().toString() : "Lazy value not initialized yet.";
    }

    @Override // kotlin.k
    @NotNull
    public Balloon getValue() {
        Balloon balloon = this.cached;
        if (balloon != null) {
            return balloon;
        }
        final c cVar = this.factory;
        Balloon balloonCreate = ((Balloon.Factory) ((Class) new z(cVar) { // from class: com.skydoves.balloon.internals.ActivityBalloonLazy$value$factory$1
            @Override // kotlin.reflect.k
            public Object get() {
                return a.b((c) this.receiver);
            }
        }.get()).getDeclaredConstructor(null).newInstance(null)).create(this.context, this.lifecycleOwner);
        this.cached = balloonCreate;
        return balloonCreate;
    }
}
