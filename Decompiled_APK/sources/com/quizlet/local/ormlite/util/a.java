package com.quizlet.local.ormlite.util;

import androidx.camera.camera2.internal.AbstractC0147y;
import com.google.android.gms.internal.mlkit_vision_barcode.C7;
import com.j256.ormlite.dao.Dao;
import io.reactivex.rxjava3.core.r;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final /* synthetic */ class a implements r {
    public final /* synthetic */ int a;
    public final /* synthetic */ Dao b;
    public final /* synthetic */ String c;

    public /* synthetic */ a(Dao dao, String str, int i) {
        this.a = i;
        this.b = dao;
        this.c = str;
    }

    @Override // io.reactivex.rxjava3.core.r
    public final void j(io.reactivex.rxjava3.internal.operators.single.c emitter) {
        switch (this.a) {
            case 0:
                Dao dao = this.b;
                String str = this.c;
                Intrinsics.checkNotNullParameter(emitter, "emitter");
                try {
                    emitter.onSuccess(dao.queryRaw(str, dao.getRawRowMapper(), new String[0]).getResults());
                    break;
                } catch (Throwable th) {
                    timber.log.c.a.g(AbstractC0147y.d("Database Query for Query:\n", str), new Object[0]);
                    if (emitter.b(th)) {
                        return;
                    }
                    C7.c(th);
                    return;
                }
            default:
                Dao dao2 = this.b;
                String str2 = this.c;
                Intrinsics.checkNotNullParameter(emitter, "emitter");
                try {
                    emitter.onSuccess(Integer.valueOf(dao2.executeRawNoArgs(str2)));
                    break;
                } catch (Throwable th2) {
                    timber.log.c.a.g(AbstractC0147y.d("Database Query for Statement:\n", str2), new Object[0]);
                    if (emitter.b(th2)) {
                        return;
                    }
                    C7.c(th2);
                }
        }
    }
}
