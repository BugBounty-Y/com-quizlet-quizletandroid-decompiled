package kotlin.io;

import java.io.File;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class d extends a {
    public boolean b;
    public File[] c;
    public int d;
    public final /* synthetic */ e e;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public d(e eVar, File rootDir) {
        super(rootDir);
        Intrinsics.checkNotNullParameter(rootDir, "rootDir");
        this.e = eVar;
    }

    @Override // kotlin.io.f
    public final File a() {
        Function2 function2;
        boolean z = this.b;
        e eVar = this.e;
        File file = this.a;
        if (z) {
            File[] fileArr = this.c;
            if (fileArr == null || this.d < fileArr.length) {
                if (fileArr == null) {
                    File[] fileArrListFiles = file.listFiles();
                    this.c = fileArrListFiles;
                    if (fileArrListFiles == null && (function2 = ((g) eVar.e).e) != null) {
                        function2.invoke(file, new AccessDeniedException(this.a, null, "Cannot list files in a directory", 2, null));
                    }
                    File[] fileArr2 = this.c;
                    if (fileArr2 == null || fileArr2.length == 0) {
                        Function1 function1 = ((g) eVar.e).d;
                        if (function1 != null) {
                            function1.invoke(file);
                        }
                    }
                }
                File[] fileArr3 = this.c;
                Intrinsics.d(fileArr3);
                int i = this.d;
                this.d = i + 1;
                return fileArr3[i];
            }
            Function1 function12 = ((g) eVar.e).d;
            if (function12 != null) {
                function12.invoke(file);
                return null;
            }
        } else {
            Function1 function13 = ((g) eVar.e).c;
            if (function13 == null || ((Boolean) function13.invoke(file)).booleanValue()) {
                this.b = true;
                return file;
            }
        }
        return null;
    }
}
