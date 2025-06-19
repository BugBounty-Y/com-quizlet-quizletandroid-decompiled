package com.quizlet.quizletandroid.util.file;

import android.content.Context;
import android.database.Cursor;
import android.net.Uri;
import androidx.glance.appwidget.protobuf.Z;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3336f;
import com.quizlet.data.repository.set.f;
import java.io.File;
import java.io.IOException;
import kotlin.Unit;
import kotlin.coroutines.h;
import kotlin.coroutines.jvm.internal.i;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.J;
import kotlinx.coroutines.C;

/* loaded from: classes3.dex */
public final class c extends i implements Function2 {
    public final /* synthetic */ f j;
    public final /* synthetic */ String k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public c(f fVar, String str, h hVar) {
        super(2, hVar);
        this.j = fVar;
        this.k = str;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final h create(Object obj, h hVar) {
        return new c(this.j, this.k, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((c) create((C) obj, (h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) throws IOException {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        f fVar = this.j;
        Uri uri = (Uri) ((com.quizlet.quizletandroid.ui.common.images.capture.a) fVar.c).h(this.k);
        J j = new J();
        Cursor cursorQuery = ((Context) fVar.b).getContentResolver().query(uri, null, null, null, null);
        if (cursorQuery != null) {
            try {
                int columnIndex = cursorQuery.getColumnIndex("_display_name");
                if (cursorQuery.moveToFirst()) {
                    j.a = cursorQuery.getString(columnIndex);
                }
                Unit unit = Unit.a;
                cursorQuery.close();
            } catch (Throwable th) {
                try {
                    throw th;
                } catch (Throwable th2) {
                    AbstractC3336f.c(cursorQuery, th);
                    throw th2;
                }
            }
        }
        String str = (String) j.a;
        if (str != null) {
            return str;
        }
        String path = uri.getPath();
        if (path != null) {
            return new File(path).getName();
        }
        return null;
    }
}
