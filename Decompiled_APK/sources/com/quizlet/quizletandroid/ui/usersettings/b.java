package com.quizlet.quizletandroid.ui.usersettings;

import android.text.TextUtils;
import com.quizlet.api.model.ApiResponse;
import com.quizlet.api.model.ApiThreeWrapper;
import com.quizlet.api.model.ProfileImage;
import io.reactivex.rxjava3.core.p;
import io.reactivex.rxjava3.functions.h;
import io.reactivex.rxjava3.functions.i;
import retrofit2.HttpException;
import retrofit2.K;

/* loaded from: classes3.dex */
public final /* synthetic */ class b implements h, i {
    public final /* synthetic */ int a;
    public final /* synthetic */ d b;

    public /* synthetic */ b(d dVar, int i) {
        this.a = i;
        this.b = dVar;
    }

    @Override // io.reactivex.rxjava3.functions.h
    public Object apply(Object obj) {
        switch (this.a) {
            case 0:
                K k = (K) obj;
                this.b.getClass();
                Object obj2 = k.b;
                return obj2 != null ? p.f((ApiThreeWrapper) obj2) : p.d(new HttpException(k));
            default:
                this.b.getClass();
                return ((ApiResponse) obj).getModelWrapper().getProfileImages();
        }
    }

    @Override // io.reactivex.rxjava3.functions.i
    public boolean test(Object obj) {
        this.b.getClass();
        return !TextUtils.isEmpty(((ProfileImage) obj).getUrl());
    }
}
