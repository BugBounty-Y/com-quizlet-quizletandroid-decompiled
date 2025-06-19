package androidx.sqlite.db;

import android.os.Parcel;
import com.google.android.gms.common.api.internal.i;
import com.google.android.gms.internal.mlkit_vision_document_scanner.u7;
import com.google.android.gms.internal.mlkit_vision_document_scanner.w7;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class a implements g, i {
    public final /* synthetic */ int a;
    public String b;

    @Override // com.google.android.gms.common.api.internal.i
    public void accept(Object obj, Object obj2) {
        com.google.android.gms.tasks.f fVar = (com.google.android.gms.tasks.f) obj2;
        u7 u7Var = (u7) ((w7) ((com.google.mlkit.vision.documentscanner.internal.e) obj).m());
        Parcel parcelObtain = Parcel.obtain();
        parcelObtain.writeInterfaceToken("com.google.mlkit.vision.docscan.ui.aidls.IDocumentScannerService");
        parcelObtain.writeString(this.b);
        Parcel parcelObtain2 = Parcel.obtain();
        try {
            u7Var.a.transact(1, parcelObtain, parcelObtain2, 0);
            parcelObtain2.readException();
            parcelObtain.recycle();
            parcelObtain2.recycle();
            fVar.b(null);
        } catch (Throwable th) {
            parcelObtain.recycle();
            parcelObtain2.recycle();
            throw th;
        }
    }

    @Override // androidx.sqlite.db.g
    public String d() {
        return this.b;
    }

    @Override // androidx.sqlite.db.g
    public void f(f statement) {
        Intrinsics.checkNotNullParameter(statement, "statement");
        Intrinsics.checkNotNullParameter(statement, "statement");
    }

    public String toString() {
        switch (this.a) {
            case 3:
                return android.support.v4.media.session.a.t(new StringBuilder("Phase('"), this.b, "')");
            default:
                return super.toString();
        }
    }

    public a(String name, int i) {
        this.a = i;
        switch (i) {
            case 2:
                this.b = name;
                break;
            case 3:
                Intrinsics.checkNotNullParameter(name, "name");
                this.b = name;
                break;
            default:
                Intrinsics.checkNotNullParameter(name, "query");
                Intrinsics.checkNotNullParameter(name, "query");
                this.b = name;
                break;
        }
    }
}
