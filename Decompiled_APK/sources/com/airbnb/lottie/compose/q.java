package com.airbnb.lottie.compose;

import android.content.Context;
import android.graphics.Typeface;
import androidx.glance.appwidget.protobuf.Z;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt;
import kotlinx.coroutines.C;

/* loaded from: classes.dex */
public final class q extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public final /* synthetic */ com.airbnb.lottie.h j;
    public final /* synthetic */ Context k;
    public final /* synthetic */ String l;
    public final /* synthetic */ String m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public q(com.airbnb.lottie.h hVar, Context context, String str, String str2, kotlin.coroutines.h hVar2) {
        super(2, hVar2);
        this.j = hVar;
        this.k = context;
        this.l = str;
        this.m = str2;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new q(this.j, this.k, this.l, this.m, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((q) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        for (com.airbnb.lottie.model.c cVar : this.j.f.values()) {
            Context context = this.k;
            Intrinsics.d(cVar);
            String str = cVar.c;
            try {
                Typeface typefaceCreateFromAsset = Typeface.createFromAsset(context.getAssets(), this.l + cVar.a + this.m);
                try {
                    Intrinsics.d(typefaceCreateFromAsset);
                    Intrinsics.checkNotNullExpressionValue(str, "getStyle(...)");
                    int i = 0;
                    boolean zG = StringsKt.G(str, "Italic", false);
                    boolean zG2 = StringsKt.G(str, "Bold", false);
                    if (zG && zG2) {
                        i = 3;
                    } else if (zG) {
                        i = 2;
                    } else if (zG2) {
                        i = 1;
                    }
                    if (typefaceCreateFromAsset.getStyle() != i) {
                        typefaceCreateFromAsset = Typeface.create(typefaceCreateFromAsset, i);
                    }
                    cVar.d = typefaceCreateFromAsset;
                } catch (Exception unused) {
                    com.airbnb.lottie.utils.c.a.getClass();
                }
            } catch (Exception unused2) {
                com.airbnb.lottie.utils.c.a.getClass();
            }
        }
        return Unit.a;
    }
}
