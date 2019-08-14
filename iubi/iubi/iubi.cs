using DPFP;
using DPFP.Capture;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using SuperWebSocket;
using System.ServiceProcess;
using System.Drawing;
using System.Threading;
using SuperSocket.SocketBase;
using System.Web.Script.Serialization;
using MySql.Data.MySqlClient;
using System.Windows.Forms;

namespace iubi
{
    public class iubi :Form, DPFP.Capture.EventHandler
    {
        public WebSocketServer appServer;
        private const string _PORT_SOCKET = "2015";

        // Controlling the state process for subcribe
        public int stateEnrroller = 0;
        // Register finger
        public DPFP.Processing.Enrollment Enroller;
        // Controller of register finger
        public DPFP.Capture.Capture Capturer;
        // Type process for execute the reader (register/validation/checkin)
        public string typeProcces = "checkin"; 
        public string bitmapDactilar = null;
        public string dedo = "";
        public bool resultRegister;
        public string ServerType = "";
        public string identificacion;

        #region METODOS DE INICIALIZACION
        /// <summary>
        /// Metodos de Control de eventos.
        /// </summary>
        /// 

        public void Setup()
        {
            Console.WriteLine("                                                                                 ");
            Console.WriteLine("                                                                                 ");
            Console.WriteLine("     ------------------------------------------------------------------------    ");
            Console.WriteLine("     ------------------------------------------------------------------------    ");
            Console.WriteLine("     --------Corriendo Servicio Lector Biometrico----------------------------    ");
            Console.WriteLine("     ------------- IP: 127.0.0.1 ---------------- Puerto:2015----------------    ");
            Console.WriteLine("     ------------------------------------------------------------------------    ");
            Console.WriteLine("     ------------------------------------------------------------------------    ");
            Thread ComThread = new Thread(() =>
            {
                Connect();
            });

            ComThread.SetApartmentState(ApartmentState.STA);
            ComThread.Start();

            appServer = new WebSocketServer();
            appServer.Setup(Convert.ToInt32(_PORT_SOCKET));
            appServer.NewMessageReceived += new SessionHandler<WebSocketSession, string>(request);
            appServer.Start();
        }

        public void Stop()
        {
            appServer.Stop();
          
        }


        void Connect()
        {
            Init();
            Start();
        }
        void Init()
        {
            try
            {
                // Create an enrollment.
                Enroller = new DPFP.Processing.Enrollment();
                // Create a capture operation.
                Capturer = new DPFP.Capture.Capture(Priority.Low); 

                UpdateStatus();

                // Subscribe for capturing events.
                if (null != Capturer) Capturer.EventHandler = this;
            }
            catch
            {

            }
        }

        private void UpdateStatus()
        {
            this.stateEnrroller = (int) Enroller.FeaturesNeeded;
        }

        public void Start()
        {
            if (null != Capturer)
            {
                try
                {
                    Capturer.StartCapture();
                    string json = @"data =
                    {
                        'type': '" + "Capture reader" + @"',
                        'payload': [
                            {
                                'state' : '" + "Inicialite" + @"'
                            }
                        ] 
                    }
                ";

                    foreach (WebSocketSession session in appServer.GetAllSessions())
                    {
                        session.Send(json);
                    }

                }
                catch
                {

                }
            }
        }

        public void Pause()
        {
            if (null != Capturer)
            {
                try
                {
                    Capturer.StopCapture();
                }
                catch
                {

                }
            }
        }
        /// <summary>
        /// Ejecuta el proceso de incripcion de la huella
        /// </summary>
        /// <param name="Sample"></param>
        private string Process(DPFP.Sample Sample)
        {
            string state = "";
            DPFP.FeatureSet features = ExtractFeatures(Sample, DPFP.Processing.DataPurpose.Enrollment);
            // Check quality of the sample and add to enroller if it's good
            if (features != null)
                try
                {
                    Enroller.AddFeatures(features);     // Add feature set to template.
                    state = "procces";
                } catch (DPFP.Error.SDKException e) {
                   
                    Enroller.Clear();
                    this.Pause();
                    Start();

                    return state = "failed";
                }

                finally
                {
                    UpdateStatus();
                    // Check if template has been created.
                    switch (Enroller.TemplateStatus)
                    {
                        case DPFP.Processing.Enrollment.Status.Ready:   // report success and stop capturing
                            DPFP.Template template = Enroller.Template;
                            MemoryStream memoryFootprint = new MemoryStream();
                            template.Serialize(memoryFootprint);
                            byte[] footprintByte = memoryFootprint.ToArray();
                            Huella _huella = new Huella();
                            _huella._identificacion = identificacion;
                            _huella._huella1 = footprintByte;
                            _huella._dedo = dedo;
                            state = resultRegister ? "complete" : "failed";
                            this.Pause();

                            break;

                        case DPFP.Processing.Enrollment.Status.Failed:  // report failure and restart capturing
                            state = "failed";
                            Enroller.Clear();
                            this.Pause();
                            Start();
                            break;
                    }

                }
            
            return state;
        }
        private bool Validate(DPFP.Sample Sample)
        {
            DPFP.FeatureSet features = ExtractFeatures(Sample, DPFP.Processing.DataPurpose.Verification);
            
            if (features != null)
            {
                UpdateStatus(); //Actualiza el estado del lector.
                return ValidateOneFingerPrint(features);
            }
            return false;
        }

        private bool ValidateOneFingerPrint(FeatureSet features)
        {
            string json = @"data =
                    {
                        'type': '" + "failed" + @"',
                        'payload': [
                            {
                                'state' : '" + "No se puede conectar a la base de datos" + @"'
                            }
                        ] 
                    }
                ";

            foreach (WebSocketSession session in appServer.GetAllSessions())
            {
                session.Send(json);
            }
            return false;

        }
        private bool VerifyFinger(byte[] byteFinger, FeatureSet features)
        {
            try
            {
                DPFP.Verification.Verification.Result resulta = new DPFP.Verification.Verification.Result();
                DPFP.Verification.Verification verify = new DPFP.Verification.Verification();
                MemoryStream stream = new MemoryStream(byteFinger);
                DPFP.Template _templates = new DPFP.Template(stream);
                _templates.DeSerialize((byte[])byteFinger);
                verify.Verify(features, _templates, ref resulta);
                return (resulta.Verified);
            }
            catch (Exception e)
            {

                string json = @"data =
                    {
                        'type': '" + "failed" + @"',
                        'payload': [
                            {
                                'state' : '" + e.ToString() + @"'
                            }
                        ] 
                    }
                ";

                foreach (WebSocketSession session in appServer.GetAllSessions())
                {
                    session.Send(json);
                }

                return false;

            }

        }

        #endregion

        #region METODOS CONVERSION DE DATOS
        public void BitMapToString(Bitmap bitmap)
        {
            Bitmap bImage = bitmap;  //Your Bitmap Image
            System.IO.MemoryStream ms = new System.IO.MemoryStream();
            bImage.Save(ms, System.Drawing.Imaging.ImageFormat.Png);
            byte[] byteImage = ms.ToArray();
            bitmapDactilar = StringToByte(byteImage);


        }
        /// <summary>
        /// Conversión de Byte[] a formato string.
        /// </summary>
        /// <param name="footprintByte"></param>
        /// <returns></returns>
        public string StringToByte(byte[] footprintByte)
        {
            return Convert.ToBase64String(footprintByte);
        }


        /// <summary>
        /// Conversor de String a Byte[]
        /// </summary>
        /// <param name="finger"></param>
        /// <returns></returns>
        public byte[] ByteToString(string finger)
        {
            //byte[] bytes = new byte[finger.Length * sizeof(char)];
            //System.Buffer.BlockCopy(finger.ToCharArray(), 0, bytes, 0, bytes.Length);
            byte[] bytes = Convert.FromBase64String(finger);
            return bytes;
        }
        /// <summary>
        /// Convierte json que se envia desde javascript a Objetos.
        /// </summary>
        /// <param name="_json"></param>


        protected DPFP.FeatureSet ExtractFeatures(DPFP.Sample Sample, DPFP.Processing.DataPurpose Purpose)
        {
            DPFP.Processing.FeatureExtraction Extractor = new DPFP.Processing.FeatureExtraction();  // Create a feature extractor
            DPFP.Capture.CaptureFeedback feedback = DPFP.Capture.CaptureFeedback.None;
            DPFP.FeatureSet features = new DPFP.FeatureSet();
            Extractor.CreateFeatureSet(Sample, Purpose, ref feedback, ref features);            // TODO: return features as a result?
            if (feedback == DPFP.Capture.CaptureFeedback.Good)
                return features;
            else
                return null;
        }
        #endregion

        #region METODOS DE CONVERSION DE IMAGEN
        protected Bitmap ConvertSampleToBitmap(DPFP.Sample Sample)
        {
            DPFP.Capture.SampleConversion Convertor = new DPFP.Capture.SampleConversion();  // Create a sample convertor.
            Bitmap bitmap = null;                                                           // TODO: the size doesn't matter
            Convertor.ConvertToPicture(Sample, ref bitmap);                                 // TODO: return bitmap as a result
            return bitmap;
        }
        #endregion

        #region SERVICIO DE WINDOWS.

        private void request(WebSocketSession session, string message)
        {
            try
            {
           
                string json = message;

                var serializer = new JavaScriptSerializer();
                serializer.RegisterConverters(new[] { new DynamicJsonConverter() });

                

                dynamic obj = serializer.Deserialize(json, typeof(object));

                string type = obj.type;


                switch (type)
                {
                    case "connectserver":
                        ServerType = obj.payload[0].type;
                        break;
                    case "register":
                        Start();
                        Enroller.Clear();
                        identificacion = obj.payload[0].user;
                        dedo = obj.payload[0].finger;
                        typeProcces = "register";
                        break;
                    case "validate":
                        Start();
                        identificacion = obj.payload[0].user;
                        typeProcces = "validate";
                        break;
                    case "checkin":
                        Start();
                        typeProcces = "checkin";
                        break;
                    default:
                        break;
                }
            }
            catch (Exception e)
            {
                string json = @"data =
                    {
                        'type': '" + "Fail input" + @"'
                    }
                ";
              
                session.Send(json);
            }

        }

        public void OnComplete(object Capture, string ReaderSerialNumber, DPFP.Sample Sample) { 
            string state = "";

            switch (typeProcces)
            {
                case "register":
                    state = Process(Sample);
                    break;
                case "validate":
                    state = Validate(Sample) ? "complete" : "failed";
                    if (state == "complete") Pause();
                    break;
                default:
                    state = "checkin";
                    break;

            }

            
            string hexString = "0x" + BitConverter.ToString(Sample.Bytes).Replace("-", string.Empty);

            // Create image of finger
            BitMapToString(ConvertSampleToBitmap(Sample));

            string json = "{ \"type\": \"" + typeProcces + "\", \"payload\": [{\"state\" : \"" + state + "\", \"enrroller\" : " + stateEnrroller + ", \"bytes\"  : \"" + hexString + "\", \"data\" : \"" + bitmapDactilar + "\" }]}";

            foreach (WebSocketSession session in appServer.GetAllSessions())
            {
                session.Send(json);
            }
        }

        public void OnReaderConnect(object Capture, string ReaderSerialNumber)
        {
            try
            {
                string json = @"data =
                    {
                        'type': '" + "connect" + @"'
                    }
                ";

                foreach (WebSocketSession session in appServer.GetAllSessions())
                {
                    session.Send(json);
                }
            }
            catch (Exception)
            {

                return;
            }


        }

        public void OnReaderDisconnect(object Capture, string ReaderSerialNumber)
        {
            try
            {
                string json = @"data =
                    {
                        'type': '" + "disconnect" + @"'
                    }
                ";

                foreach (WebSocketSession session in appServer.GetAllSessions())
                {
                    session.Send(json);
                }
            }
            catch (Exception)
            {

                return;
            }

        }

        public void OnSampleQuality(object Capture, string ReaderSerialNumber, CaptureFeedback CaptureFeedback)
        {
        }

        public void OnFingerGone(object Capture, string ReaderSerialNumber)
        {

        }

        public void OnFingerTouch(object Capture, string ReaderSerialNumber)
        {

        }
        #endregion


        #region ENTIDAD
        public class Huella
        {
            public string _identificacion { get; set; }
            public byte[] _huella1 { get; set; }
            public string _dedo { get; set; }
            public Huella() { }
            public Huella(int primaryKey, string ident, byte[] huella, string dedo)
            {
                this._identificacion = ident;
                this._huella1 = huella;
                this._dedo = dedo;
            }
        }
        #endregion
        
    }
   
}