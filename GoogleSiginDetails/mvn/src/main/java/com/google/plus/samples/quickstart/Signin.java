
package com.google.plus.samples.quickstart;

import com.google.api.client.auth.oauth2.TokenResponseException;
import com.google.api.client.googleapis.auth.oauth2.GoogleAuthorizationCodeTokenRequest;
import com.google.api.client.googleapis.auth.oauth2.GoogleClientSecrets;
import com.google.api.client.googleapis.auth.oauth2.GoogleCredential;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdToken;
import com.google.api.client.googleapis.auth.oauth2.GoogleTokenResponse;
import com.google.api.client.http.GenericUrl;
import com.google.api.client.http.HttpResponse;
import com.google.api.client.http.HttpTransport;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.jackson.JacksonFactory;
import com.google.api.services.plus.Plus;
import com.google.api.services.plus.model.PeopleFeed;
import com.google.gson.Gson;

import org.mortbay.jetty.Server;
import org.mortbay.jetty.servlet.ServletHandler;
import org.mortbay.jetty.servlet.SessionHandler;

import org.apache.log4j.BasicConfigurator;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Scanner;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;


public class Signin {
  private static final HttpTransport TRANSPORT = new NetHttpTransport();
  private static final JacksonFactory JSON_FACTORY = new JacksonFactory();

  private static final Gson GSON = new Gson();

  private static GoogleClientSecrets clientSecrets;

  static {
    try {
      Reader reader = new FileReader("client_secrets.json");
      clientSecrets = GoogleClientSecrets.load(JSON_FACTORY, reader);
    } catch (IOException e) {
      throw new Error("No client_secrets.json found", e);
    }
  }

  private static final String CLIENT_ID = clientSecrets.getWeb().getClientId();

  private static final String CLIENT_SECRET = clientSecrets.getWeb().getClientSecret();

  private static final String APPLICATION_GoogleSignIn = "Google SignIn";
  public static void main(String[] args) throws Exception {
    BasicConfigurator.configure();
    Server server = new Server(4567);
    ServletHandler servletHandler = new ServletHandler();
    SessionHandler sessionHandler = new SessionHandler();
    sessionHandler.setHandler(servletHandler);
    server.setHandler(sessionHandler);
    servletHandler.addServletWithMapping(ConnectServlet.class, "/connect");
    servletHandler.addServletWithMapping(DisconnectServlet.class, "/disconnect");
    servletHandler.addServletWithMapping(PeopleServlet.class, "/people");
    servletHandler.addServletWithMapping(MainServlet.class, "/");
    server.start();
    server.join();
  }

  /**
   * Initialize a session for the current user, and render index.html.
   */
  public static class MainServlet extends HttpServlet {

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
        throws ServletException, IOException {
      // This check serves the signin button image
      if ("/signin_button.png".equals(request.getServletPath())) {
        File staticFile = new File("./static/signin_button.png");
        FileInputStream fileStream = new FileInputStream(staticFile);
        byte []buf = new byte[(int)staticFile.length()];
        fileStream.read(buf);
        response.setContentType("image/png");
        response.getOutputStream().write(buf);
        response.setStatus(HttpServletResponse.SC_OK);
        return;
      }

      // This check prevents the "/" handler from handling all requests by default
      if (!"/".equals(request.getServletPath())) {
        response.setStatus(HttpServletResponse.SC_NOT_FOUND);
        return;
      }

      response.setContentType("text/html");
      try {
        
        String state = new BigInteger(130, new SecureRandom()).toString(32);
        request.getSession().setAttribute("state", state);
        response.getWriter().print(new Scanner(new File("index.html"), "UTF-8")
            .useDelimiter("\\A").next()
            .replaceAll("[{]{2}\\s*CLIENT_ID\\s*[}]{2}", CLIENT_ID)
            .replaceAll("[{]{2}\\s*STATE\\s*[}]{2}", state)
            .replaceAll("[{]{2}\\s*APPLICATION_NAME\\s*[}]{2}",
                APPLICATION_GoogleSignIn)
            .toString());
        response.setStatus(HttpServletResponse.SC_OK);
      } catch (FileNotFoundException e) {
        e.printStackTrace();
        response.setStatus(HttpServletResponse.SC_NOT_FOUND);
        response.getWriter().print(e.toString());
      }
    }
  }

  public static class ConnectServlet extends HttpServlet {
    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
        throws ServletException, IOException {
      response.setContentType("application/json");

      String tokenData = (String) request.getSession().getAttribute("token");
      if (tokenData != null) {
        response.setStatus(HttpServletResponse.SC_OK);
        response.getWriter().print(GSON.toJson("Current user is already connected."));
        return;
      }
      if (!request.getParameter("state").equals(request.getSession().getAttribute("state"))) {
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.getWriter().print(GSON.toJson("Invalid state parameter."));
        return;
      }
     

      ByteArrayOutputStream resultStream = new ByteArrayOutputStream();
      getContent(request.getInputStream(), resultStream);
      String code = new String(resultStream.toByteArray(), "UTF-8");

      try {
        GoogleTokenResponse tokenResponse =
            new GoogleAuthorizationCodeTokenRequest(TRANSPORT, JSON_FACTORY,
                CLIENT_ID, CLIENT_SECRET, code, "postmessage").execute();

        GoogleIdToken idToken = tokenResponse.parseIdToken();
        String gplusId = idToken.getPayload().getSubject();

        request.getSession().setAttribute("token", tokenResponse.toString());
        response.setStatus(HttpServletResponse.SC_OK);
        response.getWriter().print(GSON.toJson("Successfully connected user."));
      } catch (TokenResponseException e) {
        response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
        response.getWriter().print(GSON.toJson("Failed to upgrade the authorization code."));
      } catch (IOException e) {
        response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
        response.getWriter().print(GSON.toJson("Failed to read token data from Google. " +
            e.getMessage()));
      }
    }

    static void getContent(InputStream inputStream, ByteArrayOutputStream outputStream)
        throws IOException {
      // Read the response into a buffered stream
      BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream));
      int readChar;
      while ((readChar = reader.read()) != -1) {
        outputStream.write(readChar);
      }
      reader.close();
    }
  }
  public static class DisconnectServlet extends HttpServlet {
    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
        throws ServletException, IOException {
      response.setContentType("application/json");

      String tokenData = (String) request.getSession().getAttribute("token");
      if (tokenData == null) {
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.getWriter().print(GSON.toJson("Current user not connected."));
        return;
      }
      try {
        GoogleCredential credential = new GoogleCredential.Builder()
            .setJsonFactory(JSON_FACTORY)
            .setTransport(TRANSPORT)
            .setClientSecrets(CLIENT_ID, CLIENT_SECRET).build()
            .setFromTokenResponse(JSON_FACTORY.fromString(
                tokenData, GoogleTokenResponse.class));
        HttpResponse revokeResponse = TRANSPORT.createRequestFactory()
            .buildGetRequest(new GenericUrl(
                String.format(
                    "https://accounts.google.com/o/oauth2/revoke?token=%s",
                    credential.getAccessToken()))).execute();
        request.getSession().removeAttribute("token");
        response.setStatus(HttpServletResponse.SC_OK);
        response.getWriter().print(GSON.toJson("Successfully disconnected."));
      } catch (IOException e) {
        response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
        response.getWriter().print(GSON.toJson("Failed to revoke token for given user."));
      }
    }
  }

  public static class PeopleServlet extends HttpServlet {
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
        throws ServletException, IOException {
      response.setContentType("application/json");

      // Only fetch a list of people for connected users.
      String tokenData = (String) request.getSession().getAttribute("token");
      if (tokenData == null) {
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.getWriter().print(GSON.toJson("Current user not connected."));
        return;
      }
      try {
        GoogleCredential credential = new GoogleCredential.Builder()
            .setJsonFactory(JSON_FACTORY)
            .setTransport(TRANSPORT)
            .setClientSecrets(CLIENT_ID, CLIENT_SECRET).build()
            .setFromTokenResponse(JSON_FACTORY.fromString(
                tokenData, GoogleTokenResponse.class));
        Plus service = new Plus.Builder(TRANSPORT, JSON_FACTORY, credential)
            .setApplicationName(APPLICATION_GoogleSignIn)
            .build();
        PeopleFeed people = service.people().list("me", "visible").execute();
        response.setStatus(HttpServletResponse.SC_OK);
        response.getWriter().print(GSON.toJson(people));
      } catch (IOException e) {
        response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
        response.getWriter().print(GSON.toJson("Failed to read data from Google. " +
            e.getMessage()));
      }
    }
  }
}
