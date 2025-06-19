package androidx.compose.material;

import com.skydoves.balloon.internals.DefinitionKt;
import java.io.File;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class V extends kotlin.jvm.internal.r implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ Function0 b;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ V(int i, Function0 function0) {
        super(0);
        this.a = i;
        this.b = function0;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                this.b.invoke();
                return Boolean.TRUE;
            case 1:
                this.b.invoke();
                return Boolean.TRUE;
            case 2:
                this.b.invoke();
                return Boolean.TRUE;
            case 3:
                return Float.valueOf(kotlin.ranges.l.b(((Number) this.b.invoke()).floatValue(), DefinitionKt.NO_Float_VALUE, 1.0f));
            case 4:
                return Float.valueOf(((Number) this.b.invoke()).floatValue() < 1.0f ? 0.3f : 1.0f);
            default:
                File file = (File) this.b.invoke();
                if (Intrinsics.b(kotlin.io.k.f(file), "preferences_pb")) {
                    File absoluteFile = file.getAbsoluteFile();
                    Intrinsics.checkNotNullExpressionValue(absoluteFile, "file.absoluteFile");
                    return absoluteFile;
                }
                throw new IllegalStateException(("File extension for file: " + file + " does not match required extension for Preferences file: preferences_pb").toString());
        }
    }
}
