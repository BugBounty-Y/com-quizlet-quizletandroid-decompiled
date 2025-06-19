package com.skydoves.balloon.internals;

import android.content.Context;
import androidx.fragment.app.Fragment;
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
public final class FragmentBalloonLazy<T extends Balloon.Factory> implements k, Serializable {
    private Balloon cached;

    @NotNull
    private final c factory;

    @NotNull
    private final Fragment fragment;

    public FragmentBalloonLazy(@NotNull Fragment fragment, @NotNull c factory) {
        Intrinsics.checkNotNullParameter(fragment, "fragment");
        Intrinsics.checkNotNullParameter(factory, "factory");
        this.fragment = fragment;
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
        if (this.fragment.getContext() == null) {
            throw new IllegalArgumentException("Balloon can not be initialized. The passed fragment's context is null.");
        }
        final c cVar = this.factory;
        Balloon.Factory factory = (Balloon.Factory) ((Class) new z(cVar) { // from class: com.skydoves.balloon.internals.FragmentBalloonLazy$value$factory$1
            @Override // kotlin.reflect.k
            public Object get() {
                return a.b((c) this.receiver);
            }
        }.get()).getDeclaredConstructor(null).newInstance(null);
        J viewLifecycleOwner = this.fragment.getView() != null ? this.fragment.getViewLifecycleOwner() : this.fragment;
        Intrinsics.d(viewLifecycleOwner);
        Context contextRequireContext = this.fragment.requireContext();
        Intrinsics.checkNotNullExpressionValue(contextRequireContext, "requireContext(...)");
        Balloon balloonCreate = factory.create(contextRequireContext, viewLifecycleOwner);
        this.cached = balloonCreate;
        return balloonCreate;
    }
}
