package com.quizlet.data.repository.folderwithcreator;

import android.media.MediaPlayer;
import androidx.camera.camera2.internal.AbstractC0147y;
import androidx.work.impl.utils.q;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3738u6;
import com.quizlet.assembly.compose.listitems.r;
import com.quizlet.quizletandroid.audio.players.h;
import io.reactivex.rxjava3.core.p;
import io.reactivex.rxjava3.functions.j;
import io.reactivex.rxjava3.internal.operators.single.g;
import java.io.File;
import java.io.IOException;
import kotlin.Unit;
import kotlin.jvm.internal.Intrinsics;
import okio.AbstractC5085b;

/* loaded from: classes2.dex */
public final /* synthetic */ class a implements j {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;
    public final /* synthetic */ Object c;
    public final /* synthetic */ Object d;

    public /* synthetic */ a(Object obj, Object obj2, Object obj3, int i) {
        this.a = i;
        this.b = obj;
        this.c = obj2;
        this.d = obj3;
    }

    @Override // io.reactivex.rxjava3.functions.j
    public final Object get() throws IllegalStateException, IOException, SecurityException, IllegalArgumentException {
        switch (this.a) {
            case 0:
                e eVar = (e) this.b;
                return AbstractC3738u6.b((com.quizlet.data.connectivity.a) eVar.c, new q((g) this.c, eVar, (p) this.d, 8), new r(17)).m();
            case 1:
                h hVar = (h) this.c;
                MediaPlayer mediaPlayer = (MediaPlayer) this.d;
                timber.log.a aVar = timber.log.c.a;
                File file = (File) this.b;
                aVar.g(AbstractC0147y.d("Loading audio file ", file.getPath()), new Object[0]);
                try {
                    hVar.d.b(Unit.a);
                    mediaPlayer.reset();
                    hVar.a = file;
                    mediaPlayer.setDataSource(file.getAbsolutePath());
                    aVar.g("Loaded audio file " + file.getPath(), new Object[0]);
                    return p.f(mediaPlayer);
                } catch (Exception e) {
                    return p.d(e);
                }
            case 2:
                com.quizlet.quizletandroid.managers.audio.g gVar = (com.quizlet.quizletandroid.managers.audio.g) this.b;
                com.quizlet.quizletandroid.data.cache.c cVar = gVar.b;
                String str = (String) this.c;
                File destFile = cVar.b(str);
                if (destFile.exists()) {
                    return p.f(destFile);
                }
                File sourceFile = gVar.c.b(str);
                Intrinsics.checkNotNullExpressionValue(sourceFile, "get(...)");
                boolean zExists = sourceFile.exists();
                com.quizlet.quizletandroid.data.cache.a aVar2 = (com.quizlet.quizletandroid.data.cache.a) this.d;
                if (zExists) {
                    com.quizlet.quizletandroid.data.cache.c cVar2 = gVar.b;
                    if (Intrinsics.b(aVar2, cVar2)) {
                        try {
                            Intrinsics.checkNotNullParameter(sourceFile, "sourceFile");
                            Intrinsics.checkNotNullParameter(destFile, "destFile");
                            com.facebook.appevents.g.j(AbstractC5085b.c(AbstractC5085b.i(sourceFile)), destFile);
                            cVar2.c(destFile, str);
                        } catch (IOException e2) {
                            timber.log.c.a.e(e2);
                        }
                    }
                }
                return p.f(aVar2.b(str));
            default:
                com.quizlet.quizletandroid.ui.common.images.loading.offline.c cVar3 = (com.quizlet.quizletandroid.ui.common.images.loading.offline.c) this.b;
                com.quizlet.quizletandroid.data.cache.a aVar3 = cVar3.b;
                String str2 = (String) this.c;
                File destFile2 = aVar3.b(str2);
                Intrinsics.checkNotNullExpressionValue(destFile2, "get(...)");
                if (destFile2.exists()) {
                    return p.f(destFile2);
                }
                File sourceFile2 = cVar3.c.b(str2);
                Intrinsics.checkNotNullExpressionValue(sourceFile2, "get(...)");
                boolean zExists2 = sourceFile2.exists();
                com.quizlet.quizletandroid.data.cache.a aVar4 = (com.quizlet.quizletandroid.data.cache.a) this.d;
                if (zExists2) {
                    com.quizlet.quizletandroid.data.cache.a aVar5 = cVar3.b;
                    if (Intrinsics.b(aVar4, aVar5)) {
                        try {
                            Intrinsics.checkNotNullParameter(sourceFile2, "sourceFile");
                            Intrinsics.checkNotNullParameter(destFile2, "destFile");
                            com.facebook.appevents.g.j(AbstractC5085b.c(AbstractC5085b.i(sourceFile2)), destFile2);
                            aVar5.c(destFile2, str2);
                            sourceFile2.delete();
                        } catch (IOException e3) {
                            timber.log.c.a.e(e3);
                        }
                    }
                }
                return p.f(aVar4.b(str2));
        }
    }
}
