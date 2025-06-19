package com.quizlet.api;

import com.quizlet.api.model.AddPasswordRequest;
import com.quizlet.api.model.ApiThreeWrapper;
import com.quizlet.api.model.ChangeEmailRequest;
import com.quizlet.api.model.ChangePasswordRequest;
import com.quizlet.api.model.ChangeUsernameRequest;
import com.quizlet.api.model.DataWrapper;
import com.quizlet.api.model.ReauthenticationRequest;
import com.quizlet.api.model.SubscriptionRequest;
import com.quizlet.generated.enums.A1;
import com.quizlet.generated.enums.G1;
import io.reactivex.rxjava3.core.p;
import java.util.LinkedHashMap;
import java.util.Map;
import kotlin.Metadata;
import okhttp3.E;
import okhttp3.y;
import org.jetbrains.annotations.NotNull;
import retrofit2.K;

@Metadata
/* loaded from: classes2.dex */
public interface IQuizletApiClient {
    io.reactivex.rxjava3.internal.operators.single.g A(String str, String str2, long j, long j2, String str3, String str4, String str5);

    io.reactivex.rxjava3.internal.operators.single.g B(y yVar);

    io.reactivex.rxjava3.internal.operators.single.g a(Map map);

    io.reactivex.rxjava3.internal.operators.single.g b(String str);

    io.reactivex.rxjava3.internal.operators.single.g c(ReauthenticationRequest reauthenticationRequest);

    io.reactivex.rxjava3.internal.operators.single.g d(String str);

    io.reactivex.rxjava3.internal.operators.single.g e();

    io.reactivex.rxjava3.internal.operators.single.g f(ChangeEmailRequest changeEmailRequest);

    io.reactivex.rxjava3.internal.operators.single.g g(Map map);

    @NotNull
    p<K<ApiThreeWrapper<DataWrapper>>> getProfileImages();

    io.reactivex.rxjava3.internal.operators.single.g h(SubscriptionRequest subscriptionRequest);

    io.reactivex.rxjava3.internal.operators.single.g i();

    io.reactivex.rxjava3.internal.operators.single.g j(Map map);

    io.reactivex.rxjava3.internal.operators.single.g k(ReauthenticationRequest reauthenticationRequest);

    io.reactivex.rxjava3.internal.operators.single.g l(ChangeUsernameRequest changeUsernameRequest);

    io.reactivex.rxjava3.internal.operators.single.g m(AddPasswordRequest addPasswordRequest);

    io.reactivex.rxjava3.internal.operators.single.g n(long j);

    io.reactivex.rxjava3.internal.operators.single.g o(ChangePasswordRequest changePasswordRequest);

    io.reactivex.rxjava3.internal.operators.single.g p(String str, long j, long j2, String str2, String str3, String str4);

    io.reactivex.rxjava3.internal.operators.single.g q(E e);

    io.reactivex.rxjava3.internal.operators.single.g r(long j, long j2, String str);

    io.reactivex.rxjava3.internal.operators.single.g s(String str);

    io.reactivex.rxjava3.internal.operators.single.g t();

    io.reactivex.rxjava3.internal.operators.single.g u(E e);

    io.reactivex.rxjava3.internal.operators.single.g v(y yVar);

    io.reactivex.rxjava3.internal.operators.single.g w(String str);

    io.reactivex.rxjava3.internal.operators.single.g x(long j, G1 g1, A1 a1);

    io.reactivex.rxjava3.internal.operators.single.g y(long j, long j2, String str, int i);

    io.reactivex.rxjava3.internal.operators.single.g z(LinkedHashMap linkedHashMap);
}
