package retrofit2.converter.jackson;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3347h2;
import com.quizlet.quizletandroid.ui.common.ads.prebid.creators.c;
import com.quizlet.remote.model.search.d;
import java.lang.annotation.Annotation;
import java.lang.reflect.Type;
import java.util.regex.Pattern;
import okhttp3.w;
import retrofit2.AbstractC5185j;
import retrofit2.InterfaceC5186k;
import retrofit2.L;

/* loaded from: classes3.dex */
public final class a extends AbstractC5185j {
    public static final w c;
    public final ObjectMapper a;
    public final w b;

    static {
        Pattern pattern = w.e;
        c = AbstractC3347h2.c("application/json; charset=UTF-8");
    }

    public a(ObjectMapper objectMapper, w wVar) {
        this.a = objectMapper;
        this.b = wVar;
    }

    @Override // retrofit2.AbstractC5185j
    public final InterfaceC5186k a(Type type, Annotation[] annotationArr) {
        ObjectMapper objectMapper = this.a;
        return new d(objectMapper.writerFor(objectMapper.getTypeFactory().constructType(type)), this.b);
    }

    @Override // retrofit2.AbstractC5185j
    public final InterfaceC5186k b(Type type, Annotation[] annotationArr, L l) {
        ObjectMapper objectMapper = this.a;
        return new c(objectMapper.readerFor(objectMapper.getTypeFactory().constructType(type)), 16);
    }
}
