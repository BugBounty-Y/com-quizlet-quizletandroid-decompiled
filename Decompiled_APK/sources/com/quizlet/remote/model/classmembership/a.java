package com.quizlet.remote.model.classmembership;

import androidx.compose.foundation.text.input.internal.u;
import com.google.android.gms.internal.mlkit_vision_barcode.S;
import com.quizlet.quizletandroid.ui.joincontenttofolder.i;
import com.quizlet.remote.model.base.ApiThreeWrapper;
import com.quizlet.remote.model.classmembership.ClassMembershipsResponse;
import io.reactivex.rxjava3.functions.h;
import java.util.List;
import kotlin.collections.K;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class a implements h {
    public final /* synthetic */ u a;

    public a(u uVar) {
        this.a = uVar;
    }

    @Override // io.reactivex.rxjava3.functions.h
    public final Object apply(Object obj) {
        ClassMembershipsResponse.Models models;
        List remotes;
        ApiThreeWrapper wrapper = (ApiThreeWrapper) obj;
        Intrinsics.checkNotNullParameter(wrapper, "wrapper");
        ClassMembershipsResponse classMembershipsResponse = (ClassMembershipsResponse) wrapper.a();
        if (classMembershipsResponse == null || (models = classMembershipsResponse.d) == null || (remotes = models.a) == null) {
            return K.a;
        }
        i iVar = (i) this.a.c;
        Intrinsics.checkNotNullParameter(remotes, "remotes");
        return S.f(iVar, remotes);
    }
}
