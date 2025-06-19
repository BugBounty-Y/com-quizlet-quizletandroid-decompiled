package com.quizlet.features.setpage.utils.setpermissions;

import android.widget.Toast;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3125d6;
import com.quizlet.api.model.ApiResponse;
import com.quizlet.api.model.ApiThreeWrapper;
import com.quizlet.api.model.ModelError;
import com.quizlet.api.model.ModelWrapper;
import com.quizlet.api.model.ValidationError;
import com.quizlet.api.util.ApiErrorResolver;
import com.quizlet.db.data.models.persisted.DBEnteredSetPassword;
import com.quizlet.infra.legacysyncengine.managers.h;
import com.quizlet.login.oldlogin.o;
import com.quizlet.quizletandroid.R;
import com.quizlet.remote.exceptions.NetException;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.internal.Intrinsics;
import okhttp3.J;
import retrofit2.K;

/* loaded from: classes3.dex */
public final class e implements io.reactivex.rxjava3.functions.d {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;
    public final /* synthetic */ Object c;
    public final /* synthetic */ Object d;

    public /* synthetic */ e(Object obj, Object obj2, Object obj3, int i) {
        this.a = i;
        this.b = obj;
        this.c = obj2;
        this.d = obj3;
    }

    @Override // io.reactivex.rxjava3.functions.d
    public final void accept(Object obj) throws Exception {
        switch (this.a) {
            case 0:
                K response = (K) obj;
                Intrinsics.checkNotNullParameter(response, "response");
                f fVar = (f) this.b;
                fVar.getClass();
                ApiThreeWrapper apiThreeWrapper = (ApiThreeWrapper) response.b;
                com.quizlet.baseui.base.b bVar = (com.quizlet.baseui.base.b) this.c;
                if (apiThreeWrapper == null) {
                    Toast.makeText(bVar, R.string.could_not_sync_password, 1).show();
                    break;
                } else {
                    List responses = apiThreeWrapper.getResponses();
                    boolean z = responses != null && responses.size() > 0;
                    ModelError error = z ? ((ApiResponse) responses.get(0)).getError() : null;
                    ModelWrapper modelWrapper = z ? ((ApiResponse) responses.get(0)).getModelWrapper() : null;
                    List<DBEnteredSetPassword> enteredSetPasswords = modelWrapper != null ? modelWrapper.getEnteredSetPasswords() : null;
                    bVar.I(false);
                    if (z && error == null && enteredSetPasswords != null) {
                        DBEnteredSetPassword dBEnteredSetPassword = enteredSetPasswords.get(0);
                        if (!dBEnteredSetPassword.getDeleted()) {
                            ((com.appsflyer.a) this.d).run();
                            h hVar = fVar.c;
                            hVar.getClass();
                            hVar.a(Collections.singletonList(dBEnteredSetPassword), null);
                            break;
                        }
                    } else if (z && error != null) {
                        List<ValidationError> validationErrors = ((ApiResponse) responses.get(0)).getValidationErrors();
                        if (validationErrors != null) {
                            ArrayList arrayList = new ArrayList();
                            for (ValidationError validationError : validationErrors) {
                                Intrinsics.d(validationError);
                                arrayList.add(ApiErrorResolver.a(bVar, validationError));
                            }
                            AbstractC3125d6.d(bVar, CollectionsKt.S(arrayList, "\n", null, null, null, 62));
                            break;
                        } else {
                            AbstractC3125d6.d(bVar, ApiErrorResolver.a(bVar, error));
                            break;
                        }
                    } else {
                        try {
                            J j = response.a.g;
                            timber.log.c.a.e(responses == null ? new NetException("null result") : new NetException(j != null ? j.f() : ""));
                            AbstractC3125d6.d(bVar, bVar.getString(R.string.could_not_sync_password));
                            break;
                        } catch (IOException e) {
                            timber.log.c.a.e(e);
                            return;
                        }
                    }
                }
                break;
            default:
                Throwable error2 = (Throwable) obj;
                Intrinsics.checkNotNullParameter(error2, "error");
                o oVar = (o) this.b;
                oVar.getClass();
                timber.log.c.a.g("ANDROID-5817: handleApiClientError with error: " + error2, new Object[0]);
                oVar.B(oVar.g.x((String) this.c, error2), (String) this.d);
                break;
        }
    }
}
