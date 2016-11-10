package soot.jimple.infoflow.android.TestApps;

import soot.jimple.Stmt;
import soot.jimple.infoflow.data.AccessPath;
import soot.jimple.infoflow.results.InfoflowResults;
import soot.jimple.infoflow.results.ResultSinkInfo;
import soot.jimple.infoflow.results.ResultSourceInfo;
import soot.jimple.infoflow.solver.cfg.IInfoflowCFG;

import javax.xml.stream.XMLOutputFactory;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamWriter;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.util.Iterator;

public class TestResultSerializer {
    public static final int FILE_FORMAT_VERSION = 100;
    private boolean serializeTaintPath;
    private final IInfoflowCFG icfg;

    public TestResultSerializer() {
        this((IInfoflowCFG)null);
    }

    public TestResultSerializer(IInfoflowCFG cfg) {
        this.serializeTaintPath = false;
        this.icfg = cfg;
    }

    public void serialize(InfoflowResults results, String fileName) throws FileNotFoundException, XMLStreamException {
        FileOutputStream out = new FileOutputStream(fileName);
        XMLOutputFactory factory = XMLOutputFactory.newInstance();
        XMLStreamWriter writer = factory.createXMLStreamWriter(out);
        writer.writeStartDocument();
        writer.writeStartElement("DataFlowResults");
        writer.writeStartElement("FileFormatVersion");
        writer.writeCharacters("100");
        writer.writeEndElement();
        writer.writeStartElement("Results");
        this.writeDataFlows(results, writer);
        writer.writeEndElement();
        writer.writeEndDocument();
        writer.close();
    }

    private void writeDataFlows(InfoflowResults results, XMLStreamWriter writer) throws XMLStreamException {
        Iterator var3 = results.getResults().keySet().iterator();

        while(var3.hasNext()) {
            ResultSinkInfo sink = (ResultSinkInfo)var3.next();
            writer.writeStartElement("Result");
            this.writeSinkInfo(sink, writer);
            writer.writeStartElement("Sources");
            Iterator var5 = results.getResults().get(sink).iterator();

            while(var5.hasNext()) {
                ResultSourceInfo src = (ResultSourceInfo)var5.next();
                this.writeSourceInfo(src, writer);
            }

            writer.writeEndElement();
            writer.writeEndElement();
        }

    }

    private void writeSourceInfo(ResultSourceInfo source, XMLStreamWriter writer) throws XMLStreamException {
        writer.writeStartElement("Source");
        writer.writeStartElement("Statement");
        writer.writeCharacters(source.getSource().toString());
        writer.writeEndElement();
        if(this.icfg != null) {
            writer.writeStartElement("Method");
            writer.writeCharacters(this.icfg.getMethodOf(source.getSource()).getSignature());
            writer.writeEndElement();
        }

        this.writeAccessPath(source.getAccessPath(), writer);
        if(this.serializeTaintPath && source.getPath() != null) {
            writer.writeStartElement("TaintPath");

            for(int i = 0; i < source.getPath().length; ++i) {
                writer.writeStartElement("PathElement");
                Stmt curStmt = source.getPath()[i];
                writer.writeStartElement("Statement");
                writer.writeCharacters(curStmt.toString());
                writer.writeEndElement();
                if(this.icfg != null) {
                    writer.writeStartElement("Method");
                    writer.writeCharacters(this.icfg.getMethodOf(curStmt).getSignature());
                    writer.writeEndElement();
                }

                AccessPath curAP = source.getPathAccessPaths()[i];
                this.writeAccessPath(curAP, writer);
                writer.writeEndElement();
            }

            writer.writeEndElement();
        }

        writer.writeEndElement();
    }

    private void writeSinkInfo(ResultSinkInfo sink, XMLStreamWriter writer) throws XMLStreamException {
        writer.writeStartElement("Sink");
        writer.writeStartElement("Statement");
        writer.writeCharacters(sink.getSink().toString());
        writer.writeEndElement();
        if(this.icfg != null) {
            writer.writeStartElement("Method");
            writer.writeCharacters(this.icfg.getMethodOf(sink.getSink()).getSignature());
            writer.writeEndElement();
        }

        this.writeAccessPath(sink.getAccessPath(), writer);
        writer.writeEndElement();
    }

    private void writeAccessPath(AccessPath accessPath, XMLStreamWriter writer) throws XMLStreamException {
        writer.writeStartElement("AccessPath");
        if(accessPath.getPlainValue() != null) {
            writer.writeStartElement("Value");
            writer.writeCharacters(accessPath.getPlainValue().toString());
            writer.writeEndElement();
        }

        if(accessPath.getBaseType() != null) {
            writer.writeStartElement("Type");
            writer.writeCharacters(accessPath.getBaseType().toString());
            writer.writeEndElement();
        }

        writer.writeStartElement("TaintSubFields");
        writer.writeCharacters(accessPath.getTaintSubFields()?"true":"false");
        writer.writeEndElement();
        if(accessPath.getFieldCount() > 0) {
            writer.writeStartElement("Fields");

            for(int i = 0; i < accessPath.getFieldCount(); ++i) {
                writer.writeStartElement("Field");
                writer.writeStartElement("Value");
                writer.writeCharacters(accessPath.getFields()[i].toString());
                writer.writeEndElement();
                writer.writeStartElement("Type");
                writer.writeCharacters(accessPath.getFieldTypes()[i].toString());
                writer.writeEndElement();
                writer.writeEndElement();
            }

            writer.writeEndElement();
        }

        writer.writeEndElement();
    }

    public void setSerializeTaintPath(boolean serialize) {
        this.serializeTaintPath = serialize;
    }
}
