package com.skydoves.balloon.internals;

import android.content.Context;
import android.view.View;
import androidx.fragment.app.Fragment;
import androidx.lifecycle.J;
import androidx.lifecycle.p0;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3144f7;
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
public final class ViewBalloonLazy<T extends Balloon.Factory> implements k, Serializable {
    private Balloon cached;

    @NotNull
    private final c factory;

    @NotNull
    private final View view;

    public ViewBalloonLazy(@NotNull View view, @NotNull c factory) {
        Intrinsics.checkNotNullParameter(view, "view");
        Intrinsics.checkNotNullParameter(factory, "factory");
        this.view = view;
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

    /* JADX WARN: Multi-variable type inference failed */
    @Override // kotlin.k
    @NotNull
    public Balloon getValue() {
        Balloon balloon = this.cached;
        if (balloon != null) {
            return balloon;
        }
        Context context = this.view.getContext();
        final c cVar = this.factory;
        Balloon.Factory factory = (Balloon.Factory) ((Class) new z(cVar) { // from class: com.skydoves.balloon.internals.ViewBalloonLazy$value$factory$1
            @Override // kotlin.reflect.k
            public Object get() {
                return a.b((c) this.receiver);
            }
        }.get()).getDeclaredConstructor(null).newInstance(null);
        J jF = p0.f(this.view);
        if (jF != null) {
            Intrinsics.d(context);
            Balloon balloonCreate = factory.create(context, jF);
            this.cached = balloonCreate;
            return balloonCreate;
        }
        if (context instanceof J) {
            Balloon balloonCreate2 = factory.create(context, (J) context);
            this.cached = balloonCreate2;
            return balloonCreate2;
        }
        try {
            Fragment fragmentB = AbstractC3144f7.b(this.view);
            if (fragmentB.getContext() == null) {
                throw new IllegalArgumentException("Balloon can not be initialized. The passed fragment's context is null.");
            }
            J viewLifecycleOwner = fragmentB.getView() != null ? fragmentB.getViewLifecycleOwner() : fragmentB;
            Intrinsics.d(viewLifecycleOwner);
            Context contextRequireContext = fragmentB.requireContext();
            Intrinsics.checkNotNullExpressionValue(contextRequireContext, "requireContext(...)");
            Balloon balloonCreate3 = factory.create(contextRequireContext, viewLifecycleOwner);
            this.cached = balloonCreate3;
            return balloonCreate3;
        } catch (Exception unused) {
            throw new IllegalArgumentException("Balloon can not be initialized. The passed context is not an instance of the LifecycleOwner.");
        }
    }
}
