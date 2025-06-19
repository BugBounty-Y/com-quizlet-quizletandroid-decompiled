package com.quizlet.quizletandroid.managers.deeplinks;

import android.net.Uri;
import androidx.camera.camera2.internal.AbstractC0147y;
import com.google.android.gms.internal.ads.Yh;
import com.quizlet.api.model.ApiResponse;
import com.quizlet.api.model.ApiThreeWrapper;
import com.quizlet.api.model.ModelWrapper;
import com.quizlet.db.data.models.persisted.DBFolder;
import com.quizlet.db.data.models.persisted.DBUser;
import com.quizlet.eventlogger.EventLogger;
import com.quizlet.quizletandroid.managers.exceptions.DeepLinkAPIResponseException;
import java.util.List;
import java.util.Locale;
import kotlin.jvm.internal.Intrinsics;
import retrofit2.K;

/* loaded from: classes3.dex */
public final class g implements io.reactivex.rxjava3.functions.d {
    public final /* synthetic */ int a;
    public final /* synthetic */ Yh b;
    public final /* synthetic */ Uri c;
    public final /* synthetic */ com.quizlet.quizletandroid.ui.deeplinkinterstitial.i d;

    public /* synthetic */ g(Yh yh, Uri uri, com.quizlet.quizletandroid.ui.deeplinkinterstitial.i iVar, int i) {
        this.a = i;
        this.b = yh;
        this.c = uri;
        this.d = iVar;
    }

    @Override // io.reactivex.rxjava3.functions.d
    public final void accept(Object obj) {
        List<ApiResponse> responses;
        int i;
        switch (this.a) {
            case 0:
                K response = (K) obj;
                Intrinsics.checkNotNullParameter(response, "response");
                Yh yh = this.b;
                yh.getClass();
                ApiThreeWrapper apiThreeWrapper = (ApiThreeWrapper) response.b;
                Uri uri = this.c;
                com.quizlet.quizletandroid.ui.deeplinkinterstitial.i iVar = this.d;
                if (apiThreeWrapper != null && (responses = apiThreeWrapper.getResponses()) != null) {
                    for (ApiResponse apiResponse : responses) {
                        if (apiResponse == null) {
                            timber.log.a aVar = timber.log.c.a;
                            String uri2 = uri.toString();
                            Intrinsics.checkNotNullExpressionValue(uri2, "toString(...)");
                            Intrinsics.checkNotNullParameter(uri2, "uri");
                            aVar.h(new DeepLinkAPIResponseException(AbstractC0147y.d("Null apiResponse for uri: ", uri2)));
                        } else {
                            ModelWrapper modelWrapper = apiResponse.getModelWrapper();
                            com.quizlet.infra.androidcontracts.deeplink.a e = null;
                            String lowerCase = null;
                            e = null;
                            e = null;
                            if (modelWrapper != null) {
                                List<DBFolder> folders = modelWrapper.getFolders();
                                List<DBUser> users = modelWrapper.getUsers();
                                int i2 = 3;
                                if (folders != null && !folders.isEmpty()) {
                                    long id = folders.get(0).getId();
                                    com.quizlet.quizletandroid.util.links.a.b((EventLogger) yh.f, uri, (com.quizlet.utmhelper.c) yh.g, Long.valueOf(id), null, 3);
                                    e = new p(id);
                                } else if (users != null && !users.isEmpty()) {
                                    String lastPathSegment = uri.getLastPathSegment();
                                    if (lastPathSegment != null) {
                                        Locale locale = Locale.getDefault();
                                        Intrinsics.checkNotNullExpressionValue(locale, "getDefault(...)");
                                        lowerCase = lastPathSegment.toLowerCase(locale);
                                        Intrinsics.checkNotNullExpressionValue(lowerCase, "toLowerCase(...)");
                                    }
                                    if (lowerCase == null) {
                                        i2 = -1;
                                        i = i2;
                                        long id2 = users.get(0).getId();
                                        com.quizlet.quizletandroid.util.links.a.b((EventLogger) yh.f, uri, (com.quizlet.utmhelper.c) yh.g, Long.valueOf(id2), null, 2);
                                        e = new E(i, id2);
                                    } else {
                                        int iHashCode = lowerCase.hashCode();
                                        if (iHashCode != -683249211) {
                                            if (iHashCode != 3526737) {
                                                if (iHashCode == 853620774 && lowerCase.equals("classes")) {
                                                    i2 = 1;
                                                }
                                                i = i2;
                                                long id22 = users.get(0).getId();
                                                com.quizlet.quizletandroid.util.links.a.b((EventLogger) yh.f, uri, (com.quizlet.utmhelper.c) yh.g, Long.valueOf(id22), null, 2);
                                                e = new E(i, id22);
                                            } else {
                                                if (!lowerCase.equals("sets")) {
                                                }
                                                i = i2;
                                                long id222 = users.get(0).getId();
                                                com.quizlet.quizletandroid.util.links.a.b((EventLogger) yh.f, uri, (com.quizlet.utmhelper.c) yh.g, Long.valueOf(id222), null, 2);
                                                e = new E(i, id222);
                                            }
                                        } else if (lowerCase.equals("folders")) {
                                            i = 0;
                                            long id2222 = users.get(0).getId();
                                            com.quizlet.quizletandroid.util.links.a.b((EventLogger) yh.f, uri, (com.quizlet.utmhelper.c) yh.g, Long.valueOf(id2222), null, 2);
                                            e = new E(i, id2222);
                                        }
                                        i2 = -1;
                                        i = i2;
                                        long id22222 = users.get(0).getId();
                                        com.quizlet.quizletandroid.util.links.a.b((EventLogger) yh.f, uri, (com.quizlet.utmhelper.c) yh.g, Long.valueOf(id22222), null, 2);
                                        e = new E(i, id22222);
                                    }
                                }
                            }
                            if (e != null) {
                                yh.j(uri, iVar, e);
                                break;
                            }
                        }
                    }
                }
                yh.j(uri, iVar, new C4630d(uri));
                break;
            default:
                Throwable it2 = (Throwable) obj;
                Intrinsics.checkNotNullParameter(it2, "it");
                Yh yh2 = this.b;
                yh2.getClass();
                Uri uri3 = this.c;
                yh2.j(uri3, this.d, new C4630d(uri3));
                break;
        }
    }
}
