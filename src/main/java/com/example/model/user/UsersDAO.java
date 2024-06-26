package com.example.model.user;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;

import javax.sql.DataSource;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import lombok.NoArgsConstructor;

/**
 * DAO for users table
 */
@ApplicationScoped
@NoArgsConstructor(force = true)
public class UsersDAO {
	private final DataSource ds;

	@Inject
	public UsersDAO(DataSource ds) {
		this.ds = ds;
	}

	public ArrayList<UserDTO> getAll() throws SQLException {
		var usersModel = new ArrayList<UserDTO>();
		try (
				Connection conn = ds.getConnection();
				PreparedStatement pstmt = conn.prepareStatement("SELECT name, role FROM users");) {
			ResultSet rs = pstmt.executeQuery();
			while (rs.next()) {
				usersModel.add(new UserDTO(rs.getString("name"), rs.getString("role"), ""));
			}
		}
		return usersModel;
	}

	public UserDTO get(String name) throws SQLException {
		try (
				Connection conn = ds.getConnection();
				PreparedStatement pstmt = conn.prepareStatement("SELECT * FROM users WHERE name=?");) {
			pstmt.setString(1, name);
			ResultSet rs = pstmt.executeQuery();
			if (rs.next()) {
				return new UserDTO(rs.getString("name"), rs.getString("role"), rs.getString("password"));
			}
		}
		return null;
	}

	public void create(UserDTO userDTO) throws SQLException {
		try (
				Connection conn = ds.getConnection();
				PreparedStatement pstmt = conn
						.prepareStatement("INSERT INTO users VALUES(?, ?, ?)")) {
			pstmt.setString(1, userDTO.getName());
			pstmt.setString(2, userDTO.getRole());
			pstmt.setString(3, userDTO.getPassword());
			pstmt.executeUpdate();
		}
	}

	public void deleteAll() throws SQLException {
		try (
				Connection conn = ds.getConnection();
				PreparedStatement pstmt = conn.prepareStatement("DELETE FROM users");) {
			pstmt.executeUpdate();
		}
	}
	
}
