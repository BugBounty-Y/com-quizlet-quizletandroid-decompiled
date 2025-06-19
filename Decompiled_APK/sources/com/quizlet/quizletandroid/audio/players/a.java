package com.quizlet.quizletandroid.audio.players;

import android.content.res.AssetFileDescriptor;
import androidx.glance.appwidget.protobuf.Z;
import com.quizlet.features.folders.composables.J;
import kotlin.Unit;
import kotlin.coroutines.jvm.internal.i;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;

/* loaded from: classes3.dex */
public final class a extends i implements Function2 {
    public final /* synthetic */ c j;
    public final /* synthetic */ AssetFileDescriptor k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public a(c cVar, AssetFileDescriptor assetFileDescriptor, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.j = cVar;
        this.k = assetFileDescriptor;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new a(this.j, this.k, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((a) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        this.j.a.b(new J(this.k, 26));
        return Unit.a;
    }
}
