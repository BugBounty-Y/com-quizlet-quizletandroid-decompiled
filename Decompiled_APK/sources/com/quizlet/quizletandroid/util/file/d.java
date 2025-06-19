package com.quizlet.quizletandroid.util.file;

import android.content.Context;
import android.database.Cursor;
import android.net.Uri;
import androidx.glance.appwidget.protobuf.Z;
import com.quizlet.data.repository.set.f;
import java.io.File;
import java.io.IOException;
import kotlin.Unit;
import kotlin.coroutines.h;
import kotlin.coroutines.jvm.internal.i;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.J;
import kotlinx.coroutines.C;

/* loaded from: classes3.dex */
public final class d extends i implements Function2 {
    public final /* synthetic */ f j;
    public final /* synthetic */ String k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public d(f fVar, String str, h hVar) {
        super(2, hVar);
        this.j = fVar;
        this.k = str;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final h create(Object obj, h hVar) {
        return new d(this.j, this.k, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((d) create((C) obj, (h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) throws IOException {
        long length;
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        f fVar = this.j;
        Uri uri = (Uri) ((com.quizlet.quizletandroid.ui.common.images.capture.a) fVar.c).h(this.k);
        J j = new J();
        Cursor cursorQuery = ((Context) fVar.b).getContentResolver().query(uri, null, null, null, null);
        if (cursorQuery != null) {
            try {
                int columnIndex = cursorQuery.getColumnIndex("_size");
                if (cursorQuery.moveToFirst()) {
                    j.a = new Long(cursorQuery.getLong(columnIndex));
                }
                Unit unit = Unit.a;
                cursorQuery.close();
            } finally {
            }
        }
        Long l = (Long) j.a;
        if (l != null) {
            length = l.longValue();
        } else {
            if (!Intrinsics.b(uri.getScheme(), "file")) {
                throw new IllegalArgumentException(android.support.v4.media.session.a.h(uri, "Uri lacks 'file' scheme: ").toString());
            }
            String path = uri.getPath();
            if (path == null) {
                throw new IllegalArgumentException(android.support.v4.media.session.a.h(uri, "Uri path is null: ").toString());
            }
            length = new File(path).length();
        }
        return new Long(length / 1024);
    }
}
