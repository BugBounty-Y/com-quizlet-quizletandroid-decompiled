package com.quizlet.data.repository.activitycenter;

import android.content.Context;
import android.net.Uri;
import com.braze.requests.framework.o;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3738u6;
import com.quizlet.assembly.compose.listitems.r;
import com.quizlet.data.repository.classfolder.e;
import com.quizlet.db.data.database.DatabaseHelper;
import com.quizlet.db.data.models.persisted.DBImage;
import com.quizlet.db.data.models.persisted.base.Models;
import com.quizlet.db.data.models.persisted.fields.DBImageFields;
import com.quizlet.db.data.net.tasks.ExecutionRouter;
import com.quizlet.features.setpage.viewmodel.P;
import com.quizlet.infra.legacysyncengine.net.request.i;
import com.quizlet.infra.legacysyncengine.tasks.parse.g;
import com.quizlet.infra.legacysyncengine.tasks.parse.h;
import com.quizlet.remote.exceptions.NetException;
import io.reactivex.rxjava3.core.p;
import io.reactivex.rxjava3.functions.j;
import io.reactivex.rxjava3.internal.operators.maybe.w;
import io.reactivex.rxjava3.internal.operators.observable.E;
import io.reactivex.rxjava3.internal.operators.single.d;
import java.io.File;
import java.io.IOException;
import java.io.PipedInputStream;
import java.io.PipedOutputStream;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import kotlin.jvm.internal.Intrinsics;
import timber.log.c;

/* loaded from: classes2.dex */
public final /* synthetic */ class a implements j {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;

    public /* synthetic */ a(Object obj, int i) {
        this.a = i;
        this.b = obj;
    }

    @Override // io.reactivex.rxjava3.functions.j
    public final Object get() {
        PipedOutputStream pipedOutputStream;
        List<DBImage> arrayList;
        switch (this.a) {
            case 0:
                b bVar = (b) this.b;
                return AbstractC3738u6.b((com.quizlet.data.connectivity.a) bVar.c, new o(bVar, 24), new r(18));
            case 1:
                P p = (P) this.b;
                return p.x1.h().g(new com.lyft.android.scissors.b(p, 19));
            case 2:
                return ((e) this.b).o(1, null);
            case 3:
                com.quizlet.infra.legacysyncengine.net.request.b bVar2 = (com.quizlet.infra.legacysyncengine.net.request.b) this.b;
                PipedInputStream pipedInputStream = new PipedInputStream();
                try {
                    pipedOutputStream = new PipedOutputStream(pipedInputStream);
                } catch (IOException e) {
                    c.a(e);
                    pipedOutputStream = null;
                }
                g gVarA = bVar2.a(pipedOutputStream);
                ExecutionRouter executionRouter = (ExecutionRouter) bVar2.a;
                executionRouter.h(gVarA);
                androidx.work.impl.model.c cVar = (androidx.work.impl.model.c) bVar2.c;
                io.reactivex.rxjava3.internal.operators.maybe.e eVar = new io.reactivex.rxjava3.internal.operators.maybe.e(new com.quizlet.data.repository.classfolder.b(7, cVar, pipedInputStream), 1);
                io.reactivex.rxjava3.core.o oVar = (io.reactivex.rxjava3.core.o) cVar.c;
                Objects.requireNonNull(oVar, "scheduler is null");
                io.reactivex.rxjava3.internal.operators.maybe.r rVar = new io.reactivex.rxjava3.internal.operators.maybe.r(eVar, oVar, 1);
                io.reactivex.rxjava3.core.o oVarI = executionRouter.i();
                Objects.requireNonNull(oVarI, "scheduler is null");
                io.reactivex.rxjava3.internal.operators.maybe.j jVar = new io.reactivex.rxjava3.internal.operators.maybe.j(new io.reactivex.rxjava3.internal.operators.maybe.r(rVar, oVarI, 0), new com.quizlet.infra.legacysyncengine.net.request.a(bVar2, 2), 1);
                Map map = Collections.EMPTY_MAP;
                return new d(new w(3, new w(0, jVar, new h(map, map, new i(new NetException("Unable to parse network stream"), null, null), null)), new com.quizlet.infra.legacysyncengine.net.request.g(0)), new com.quizlet.analytics.marketing.e(bVar2, 15), 2);
            case 4:
                String str = (String) this.b;
                try {
                    com.quizlet.data.repository.studysetwithcreatorinclass.g gVar = new com.quizlet.data.repository.studysetwithcreatorinclass.g(11);
                    gVar.c = "GET";
                    gVar.b = str;
                    return p.f(gVar.d());
                } catch (Exception e2) {
                    return p.d(e2);
                }
            default:
                com.quizlet.quizletandroid.data.net.synchooks.a aVar = (com.quizlet.quizletandroid.data.net.synchooks.a) this.b;
                DatabaseHelper databaseHelper = aVar.b;
                HashSet hashSet = new HashSet();
                StringBuilder sb = new StringBuilder();
                Context context = (Context) aVar.c;
                sb.append(context.getExternalFilesDir(null));
                sb.append("termimages");
                ArrayList arrayListG = com.facebook.appevents.g.g(new File(sb.toString()));
                ArrayList arrayListG2 = com.facebook.appevents.g.g(new File(context.getFilesDir() + "termimages"));
                ArrayList arrayList2 = new ArrayList(arrayListG2.size() + arrayListG.size());
                arrayList2.addAll(arrayListG);
                arrayList2.addAll(arrayListG2);
                Iterator it2 = arrayList2.iterator();
                while (it2.hasNext()) {
                    File file = (File) it2.next();
                    Intrinsics.checkNotNullParameter(file, "file");
                    String string = Uri.fromFile(file).toString();
                    Intrinsics.checkNotNullExpressionValue(string, "toString(...)");
                    hashSet.add(string);
                }
                ArrayList arrayList3 = new ArrayList();
                HashSet hashSet2 = new HashSet();
                try {
                    arrayList = databaseHelper.r(Models.IMAGE, true).isNotNull(DBImageFields.Names.LOCAL_PATH).query();
                } catch (SQLException e3) {
                    c.a(e3);
                    arrayList = new ArrayList();
                }
                for (DBImage dBImage : arrayList) {
                    if (dBImage.getIdentity().hasServerIdentity() || dBImage.getDeleted()) {
                        dBImage.setLocalPath(null);
                        arrayList3.add(dBImage);
                    } else {
                        String localPath = dBImage.getLocalPath();
                        if (hashSet.contains(localPath)) {
                            hashSet2.add(localPath);
                        }
                    }
                }
                hashSet.removeAll(hashSet2);
                Iterator it3 = hashSet.iterator();
                while (it3.hasNext()) {
                    String uriString = (String) it3.next();
                    Intrinsics.checkNotNullParameter(uriString, "uriString");
                    Uri uri = Uri.parse(uriString);
                    Intrinsics.checkNotNullExpressionValue(uri, "parse(...)");
                    Intrinsics.checkNotNullParameter(uri, "uri");
                    String path = uri.getPath();
                    if (path == null) {
                        throw new NullPointerException("URI path cannot be null");
                    }
                    if (!com.facebook.appevents.g.d(new File(path))) {
                        c.a.g("Unable to delete file at %s", uriString);
                    }
                }
                try {
                    databaseHelper.q(arrayList3);
                } catch (SQLException e4) {
                    c.a(e4);
                }
                return E.a;
        }
    }
}
